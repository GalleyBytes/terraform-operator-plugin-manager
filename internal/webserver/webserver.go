package webserver

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	tfv1beta1 "github.com/galleybytes/terraform-operator/pkg/apis/tf/v1beta1"
	"github.com/mattbaird/jsonpatch"
	admission "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecFactory  = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecFactory.UniversalDeserializer()
	jsonPatchType = admission.PatchTypeJSONPatch
)

// add kind AdmissionReview in scheme
func init() {
	_ = admission.AddToScheme(runtimeScheme)
	_ = tfv1beta1.AddToScheme(runtimeScheme)
}

type pluginOption struct {
	SkipAnnotaiton string               `json:"skipAnnotation"`
	PluginConfig   tfv1beta1.Plugin     `json:"pluginConfig"`
	TaskOption     tfv1beta1.TaskOption `json:"taskConfig"`
}

type mutationHandler struct {
	pluginMutationsFilepath string
	resource                metav1.GroupVersionResource
}

func newPluginOption(dir, file string) (*pluginOption, error) {
	var opt pluginOption
	filename := filepath.Join(dir, file)
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Error reading plugin mutations file '%s'", filename)
		// return nilPatch()
	}

	err = json.Unmarshal(b, &opt)
	if err != nil {
		return nil, fmt.Errorf("Error parsing plugin data from file '%s'", filename)
	}

	return &opt, nil
}

func (m mutationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	admissionHandler(w, r, m.mutate)
}

// pluginExists checks existance of plugins in the spec and checks if the plugin already exists
func (m mutationHandler) updatePlugins(tf *tfv1beta1.Terraform, pluginName tfv1beta1.TaskName, plugin tfv1beta1.Plugin) bool {
	// overwrites is only used to determine is the plugin was an overwrite or a new plugin definition
	var overwrites = false
	if tf.Spec.Plugins == nil {
		tf.Spec.Plugins = make(map[tfv1beta1.TaskName]tfv1beta1.Plugin)
	}
	for key := range tf.Spec.Plugins {
		if string(key) == string(pluginName) {
			overwrites = true
		}
	}
	tf.Spec.Plugins[pluginName] = plugin
	return overwrites
}

func doSkip(tf *tfv1beta1.Terraform, skipKey string) bool {
	if tf.ObjectMeta.Annotations == nil {
		tf.ObjectMeta.Annotations = make(map[string]string)
	}

	if _, found := tf.ObjectMeta.Annotations[skipKey]; found {
		return true
	}
	return false

}

// findTaskOptionIndex returns the index only when all the following are met:
//  1. `spec.taskOptions` exist
//  2. the `for` list only contains a single item
//  3. the item in the `for` list is the pluginName
func findTaskOptionIndex(tf *tfv1beta1.Terraform, pluginName tfv1beta1.TaskName) int {
	for i, taskOption := range tf.Spec.TaskOptions {
		if len(taskOption.For) == 1 {
			if taskOption.For[0] == pluginName {
				return i
			}
		}
	}
	return -1
}

func mergeTaskOptions(oldTaskOption, newTaskOption tfv1beta1.TaskOption) tfv1beta1.TaskOption {
	envIndexMap := map[string]int{}
	envFromIndexMap := map[corev1.EnvFromSource]int{}
	for i, env := range newTaskOption.Env {
		envIndexMap[env.Name] = i
	}
	for i, envFromSource := range newTaskOption.EnvFrom {
		envFromIndexMap[envFromSource] = i
	}

	for i, env := range oldTaskOption.Env {
		if _, found := envIndexMap[env.Name]; !found {
			continue
		}
		oldTaskOption.Env[i] = newTaskOption.Env[envIndexMap[env.Name]]
		delete(envIndexMap, env.Name)

	}
	for _, i := range envIndexMap {
		oldTaskOption.Env = append(oldTaskOption.Env, newTaskOption.Env[i])
	}

	for i, envFromSource := range oldTaskOption.EnvFrom {
		if _, found := envFromIndexMap[envFromSource]; !found {
			continue
		}
		oldTaskOption.EnvFrom[i] = newTaskOption.EnvFrom[envFromIndexMap[envFromSource]]
		delete(envFromIndexMap, envFromSource)
	}
	for _, i := range envFromIndexMap {
		oldTaskOption.EnvFrom = append(oldTaskOption.EnvFrom, newTaskOption.EnvFrom[i])
	}

	// TODO policyRules

	for k, v := range newTaskOption.Labels {
		oldTaskOption.Labels[k] = v
	}
	for k, v := range newTaskOption.Annotations {
		oldTaskOption.Annotations[k] = v
	}

	oldTaskOption.RestartPolicy = newTaskOption.RestartPolicy
	oldTaskOption.Resources = newTaskOption.Resources
	newTaskOption.Script.DeepCopyInto(&oldTaskOption.Script)

	return oldTaskOption
}

func (m *mutationHandler) mutate(ar admission.AdmissionReview) *admission.AdmissionResponse {
	if ar.Request.Resource != m.resource {
		log.Printf("WARNING Expect resource to be %s", m.resource)
		return nilPatch()
	}
	objectJSON := ar.Request.Object.Raw
	terraform, err := decodeTerraform(objectJSON)
	if err != nil {
		log.Println(err)
		return &admission.AdmissionResponse{Result: &metav1.Status{Message: err.Error()}}
	}

	for _, file := range ls(m.pluginMutationsFilepath) {
		if file.IsDir() {
			continue
		}
		filename := file.Name()
		if strings.HasPrefix(filename, ".") {
			continue
		}
		log.Println(filename)

		pluginName := tfv1beta1.TaskName(filename)

		opt, err := newPluginOption(m.pluginMutationsFilepath, filename)
		if err != nil {
			return nilPatch()
		}

		// Every plugin config has the option to not mutate if the resource contains the escape key
		if doSkip(terraform, opt.SkipAnnotaiton) {
			continue
		}

		if m.updatePlugins(terraform, pluginName, opt.PluginConfig) {
			log.Printf("Overwriting existing '%s' plugin", pluginName)
		}

		if terraform.Spec.TaskOptions == nil {
			terraform.Spec.TaskOptions = []tfv1beta1.TaskOption{}
		}

		taskOptionIndex := findTaskOptionIndex(terraform, pluginName)
		if taskOptionIndex > -1 {
			// Special consideration for mutating here becuase there are arrays of complex objects to take into account
			terraform.Spec.TaskOptions[taskOptionIndex] = mergeTaskOptions(terraform.Spec.TaskOptions[taskOptionIndex], opt.TaskOption)
			// opt.TaskOption.DeepCopyInto(&)
		} else {
			terraform.Spec.TaskOptions = append(terraform.Spec.TaskOptions, opt.TaskOption)
			taskOptionIndex = len(terraform.Spec.TaskOptions) - 1
		}
		// Ensure ONLY this plugin
		terraform.Spec.TaskOptions[taskOptionIndex].For = []tfv1beta1.TaskName{pluginName}
		if terraform.Spec.TaskOptions[taskOptionIndex].RestartPolicy == "" {
			terraform.Spec.TaskOptions[taskOptionIndex].RestartPolicy = corev1.RestartPolicyAlways
		}

		_ = corev1.Pod{}

	}

	targetJson, err := json.Marshal(terraform)
	if err != nil {
		return &admission.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	patch, err := jsonpatch.CreatePatch(objectJSON, targetJson)
	if err != nil {
		return &admission.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	realPatch := []jsonpatch.JsonPatchOperation{}
	for _, p := range patch {
		if strings.HasPrefix(p.Path, "/status") {
			continue
		}
		realPatch = append(realPatch, p)
		log.Println(p)
	}

	if len(realPatch) == 0 {
		log.Println("No patches to do")
		return nilPatch()
	}

	patchJSON, err := json.Marshal(realPatch)
	if err != nil {
		return &admission.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}
	return &admission.AdmissionResponse{Allowed: true, PatchType: &jsonPatchType, Patch: patchJSON}
}

func ls(dir string) []fs.FileInfo {
	b, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Panic(err)
	}
	return b
}

func decodeTerraform(raw []byte) (*tfv1beta1.Terraform, error) {
	terraform := tfv1beta1.Terraform{}

	if _, _, err := deserializer.Decode(raw, nil, &terraform); err != nil {
		return nil, err
	}
	return &terraform, nil
}

// admissionHandler handles the http portion of a request prior to handing to an admissionFunc function
func admissionHandler(w http.ResponseWriter, r *http.Request, admissionFunc func(admission.AdmissionReview) *admission.AdmissionResponse) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		log.Printf("contentType=%s, expect application/json", contentType)
		return
	}

	var responseObj runtime.Object
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		log.Println(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	requestedAdmissionReview, ok := obj.(*admission.AdmissionReview)
	if !ok {
		log.Printf("Expected v1.AdmissionReview but got: %T", obj)
		return
	}

	responseAdmissionReview := &admission.AdmissionReview{}
	responseAdmissionReview.SetGroupVersionKind(*gvk)
	responseAdmissionReview.Response = admissionFunc(*requestedAdmissionReview)
	responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
	responseObj = responseAdmissionReview

	respBytes, err := json.Marshal(responseObj)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		log.Println(err)
	}
}

// Return an empty patch to satisfy the response
func nilPatch() *admission.AdmissionResponse {
	return &admission.AdmissionResponse{Allowed: true, PatchType: &jsonPatchType, Patch: []byte("[]")}
}

func terraformsResource() metav1.GroupVersionResource {
	group := tfv1beta1.SchemeGroupVersion.Group
	version := tfv1beta1.SchemeGroupVersion.Version
	return metav1.GroupVersionResource{Group: group, Version: version, Resource: "terraforms"}
}

// Run starts the webserver and blocks
func Run(tlsCertFilename, tlsKeyFilename, pluginMutationsFilepath string) {
	server := http.NewServeMux()
	server.Handle("/mutate", mutationHandler{
		pluginMutationsFilepath: pluginMutationsFilepath,
		resource:                terraformsResource(),
	})

	log.Printf("Server started ...")
	err := http.ListenAndServeTLS(":8443", tlsCertFilename, tlsKeyFilename, server)
	log.Fatal(err)
}
