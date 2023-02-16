package webserver

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	tfv1alpha2 "github.com/isaaguilar/terraform-operator/pkg/apis/tf/v1alpha2"
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
	_ = tfv1alpha2.AddToScheme(runtimeScheme)
}

type access struct {
	apiServiceHost string
	apiUsername    string
	apiPassword    string
}

func (a access) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	url := fmt.Sprintf("%s/login", a.apiServiceHost)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	jsonData, err := json.Marshal(map[string]interface{}{
		"user":     a.apiUsername,
		"password": a.apiPassword,
	})
	if err != nil {
		log.Panic(err)
	}

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Panic(err)
	}

	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	response, err := client.Do(request)
	if err != nil {
		log.Panic(err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		log.Panicf("Request to %s returned a %d but expected 200", request.URL, response.StatusCode)
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Panic(err)
	}

	loginResponseData := struct {
		Data []string `json:"data"`
	}{}
	err = json.Unmarshal(responseBody, &loginResponseData)
	if err != nil {
		log.Panic(err)
	}

	fmt.Fprintf(w, `{"host": "%s", "token": "%s"}`, a.apiServiceHost, loginResponseData.Data[0])
}

type pluginMutation struct {
	Image           string            `json:"image"`
	ImagePullPolicy corev1.PullPolicy `json:"image_pull_policy"`
	EscapeKey       string            `json:"escape_key"`
	ConfigMapKeyMap map[string]string `json:"config_map_key_map"`
}

type mutationHandler struct {
	pluginMutationsFilename string
	pluginMutations         map[tfv1alpha2.TaskName]pluginMutation
}

func (m mutationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	admissionHandler(w, r, m.mutate)
}

func (m *mutationHandler) mutate(ar admission.AdmissionReview) *admission.AdmissionResponse {
	b, err := ioutil.ReadFile(m.pluginMutationsFilename)
	if err != nil {
		log.Printf("Error reading plugin mutations file '%s'", m.pluginMutationsFilename)
		return nilPatch()
	}

	err = json.Unmarshal(b, &m.pluginMutations)
	if err != nil {
		log.Printf("Error parsing plugin mutations file '%s'", m.pluginMutationsFilename)
		return nilPatch()
	}

	group := tfv1alpha2.SchemeGroupVersion.Group
	version := tfv1alpha2.SchemeGroupVersion.Version
	terraformResource := metav1.GroupVersionResource{Group: group, Version: version, Resource: "terraforms"}
	if ar.Request.Resource != terraformResource {
		log.Printf("expect resource to be %s", terraformResource)
		return nil
	}
	raw := ar.Request.Object.Raw
	terraform := tfv1alpha2.Terraform{}

	if _, _, err := deserializer.Decode(raw, nil, &terraform); err != nil {
		log.Println(err)
		return &admission.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	for name, mutation := range m.pluginMutations {

		// After the decode process, check if the resource needs mutations
		if terraform.ObjectMeta.Annotations == nil {
			terraform.ObjectMeta.Annotations = make(map[string]string)
		} else if _, found := terraform.ObjectMeta.Annotations[mutation.EscapeKey]; found {
			// An escape route from mutating based on annotations
			return nilPatch()
		}

		if terraform.Spec.Plugins == nil {
			terraform.Spec.Plugins = make(map[tfv1alpha2.TaskName]tfv1alpha2.Plugin)
		} else {
			for key := range terraform.Spec.Plugins {
				if key == name {
					log.Printf("Overwriting existing '%s' plugin", name)
				}
			}
		}

		terraform.Spec.Plugins[name] = tfv1alpha2.Plugin{
			ImageConfig: tfv1alpha2.ImageConfig{
				Image:           mutation.Image,
				ImagePullPolicy: mutation.ImagePullPolicy,
			},
			Task: tfv1alpha2.RunSetup,
			When: "After",
		}

		if terraform.Spec.TaskOptions == nil {
			terraform.Spec.TaskOptions = []tfv1alpha2.TaskOption{}
		}

		taskOptionIndex := -1
		for i, taskOption := range terraform.Spec.TaskOptions {
			// Check for the existence of the plugin in task options to append to it and not completely replace it
			if len(taskOption.For) == 1 {
				if taskOption.For[0] == name {
					log.Printf("Found taskOptions for %s", name)
					taskOptionIndex = i
				}
			}
		}

		if taskOptionIndex > -1 {
			// Monitor exists, now check the envs to update
			for i, env := range terraform.Spec.TaskOptions[taskOptionIndex].Env {
				if val, found := mutation.ConfigMapKeyMap[env.Name]; found {
					log.Printf("Found env '%s' in index %d of '%s' taskOption", env.Name, i, name)
					terraform.Spec.TaskOptions[taskOptionIndex].Env[i] = corev1.EnvVar{
						Name:  env.Name,
						Value: val,
					}
					delete(mutation.ConfigMapKeyMap, env.Name)
				}
			}

			// Generate new envs from the remaining keys
			envs := []corev1.EnvVar{}

			for key, val := range mutation.ConfigMapKeyMap {
				fmt.Printf("Adding new env '%s' to envs of '%s' taskOption", key, name)
				envs = append(envs, corev1.EnvVar{
					Name:  key,
					Value: val,
				})
			}

			terraform.Spec.TaskOptions[taskOptionIndex].Env = append(terraform.Spec.TaskOptions[taskOptionIndex].Env, envs...)
			terraform.Spec.TaskOptions[taskOptionIndex].RestartPolicy = corev1.RestartPolicyAlways
		} else {
			envs := []corev1.EnvVar{}

			for key, val := range mutation.ConfigMapKeyMap {
				log.Printf("Adding new env '%s' to envs of '%s' taskOption", key, name)
				envs = append(envs, corev1.EnvVar{
					Name:  key,
					Value: val,
				})
			}
			terraform.Spec.TaskOptions = append(terraform.Spec.TaskOptions, tfv1alpha2.TaskOption{
				For:           []tfv1alpha2.TaskName{name},
				Env:           envs,
				RestartPolicy: corev1.RestartPolicyAlways,
			})
		}
	}

	targetJson, err := json.Marshal(terraform)
	if err != nil {
		return &admission.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	patch, err := jsonpatch.CreatePatch(raw, targetJson)
	if err != nil {
		return &admission.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	terraformPatch, err := json.Marshal(patch)
	if err != nil {
		return &admission.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}
	for _, p := range patch {
		log.Println(p)
	}
	return &admission.AdmissionResponse{Allowed: true, PatchType: &jsonPatchType, Patch: terraformPatch}
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

// Run starts the webserver and blocks
func Run(tlsCertFilename, tlsKeyFilename, pluginMutationsFilename, apiServiceHost, apiUsername, apiPassword string) {
	server := http.NewServeMux()
	server.Handle("/mutate", mutationHandler{
		pluginMutationsFilename: pluginMutationsFilename,
	})
	server.Handle("/api-token-please", access{
		apiServiceHost: apiServiceHost,
		apiUsername:    apiUsername,
		apiPassword:    apiPassword,
	})
	log.Printf("Server started ...")
	err := http.ListenAndServeTLS(":8443", tlsCertFilename, tlsKeyFilename, server)
	log.Fatal(err)
}
