package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/galleybytes/terraform-operator-plugin-manager/internal/webserver"
	"github.com/isaaguilar/selfsigned"
	addmissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	// MutationWebhookConfiguration Setup
	namespace                        string
	caKeyFilename                    string
	caCertFilename                   string
	tlsKeyFilename                   string
	tlsCertFilename                  string
	mutatingWebhookConfigurationName string
	serviceName                      string
	secretName                       string
	// TFO Plugin Mutations
	pluginMutationsFilename string
	// API access
	apiServiceHost string
	apiUsername    string
	apiPassword    string
)

func getFlags() {
	flag.StringVar(&caKeyFilename, "ca-key", "/etc/certs/ca.key", "Path to the CA key")
	flag.StringVar(&caCertFilename, "ca-cert", "/etc/certs/ca.crt", "Path to the CA certificate")
	flag.StringVar(&tlsKeyFilename, "tls-key", "/etc/certs/tls.key", "Path to the TLS key")
	flag.StringVar(&tlsCertFilename, "tls-cert", "/etc/certs/tls.crt", "Path to the TLS certificate")
	flag.StringVar(&secretName, "secret-name", "terraform-operator-plugin-manager-certs", "Name of the secret used to mount certs")
	flag.StringVar(&namespace, "namespace", "tf-system", "Namespace the service is deployed into")
	flag.StringVar(&mutatingWebhookConfigurationName, "mutating-webhook-configuration-name", "terraform-operator-plugin-manager", "Name of webhook resource")
	flag.StringVar(&apiServiceHost, "api", "http://terraform-operator-api.tf-system.svc", "TFO api host - proto://host:port")
	flag.StringVar(&serviceName, "service-name", "terraform-operator-plugin-manager", "Name of the service to back up mutating webhook configuration")
	flag.StringVar(&pluginMutationsFilename, "plugin-mutations", "/plugin/mutations.json", "Path to plugin mutations")
	flag.Parse()

	apiUsername = os.Getenv("API_USERNAME")
	apiPassword = os.Getenv("API_PASSWORD")
}

// getClientOrDie returns the core k8s client.
func getClientOrDie(kubeconfigPath string) kubernetes.Interface {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		log.Fatal("Failed to get config for clientset")
	}
	return kubernetes.NewForConfigOrDie(config)
}

type Manager struct {
	ctx                              context.Context
	clientset                        kubernetes.Interface
	caKeyFilename                    string
	caCertFilename                   string
	tlsKeyFilename                   string
	tlsCertFilename                  string
	namespace                        string
	secretName                       string
	serviceName                      string
	dnsNames                         []string
	mutatingWebhookConfigurationName string
	isReadyCh                        chan (bool)
	started                          bool
}

func (m Manager) GetOrCreateSecret() *corev1.Secret {
	secretClient := m.clientset.CoreV1().Secrets(m.namespace)

	secret, err := secretClient.Get(m.ctx, m.secretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			selfSignedCert := selfsigned.NewSelfSignedCertOrDie(m.dnsNames)
			secret, err = secretClient.Create(
				m.ctx,
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      m.secretName,
						Namespace: m.namespace,
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"ca.key":  selfSignedCert.CAKey,
						"ca.crt":  selfSignedCert.CACert,
						"tls.crt": selfSignedCert.TLSCert,
						"tls.key": selfSignedCert.TLSKey,
					},
				},
				metav1.CreateOptions{},
			)
			if err != nil {
				log.Panic(err)
			}
			log.Printf("Created TLS certs in secret/%s\n", secret.Name)
		} else {
			log.Panic(err)
		}
	}
	return secret
}

func (m Manager) UpdateSecret(selfSignedCert *selfsigned.SelfSignedCert) *corev1.Secret {
	err := selfSignedCert.UpdateTLS()
	if err != nil {
		log.Panic(err)
	}
	secretClient := m.clientset.CoreV1().Secrets(m.namespace)
	secret, err := secretClient.Get(m.ctx, m.secretName, metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		log.Panicf("Expected secret '%s' to exist but was not found", m.secretName)
	}
	secret.Data = map[string][]byte{
		"ca.key":  selfSignedCert.CAKey,
		"ca.crt":  selfSignedCert.CACert,
		"tls.crt": selfSignedCert.TLSCert,
		"tls.key": selfSignedCert.TLSKey,
	}

	secret, err = secretClient.Update(m.ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		log.Panic(err)
	}

	return secret
}

func x509Cert(certData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, xerr := x509.ParseCertificate(block.Bytes)
	if xerr != nil {
		return nil, fmt.Errorf("failed to parse certificate: " + xerr.Error())
	}
	return cert, nil
}

// isCertValid checks cert expiration and cert dns names
func isCertValid(caCertData, tlsCertData []byte, dnsNames []string) bool {
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caCertData)
	if !ok {
		log.Println("failed to parse root certificate")
		return false
	}

	cert, err := x509Cert(tlsCertData)
	if err != nil {
		log.Println(err.Error())
		return false
	}

	t := time.Now()
	opts := x509.VerifyOptions{
		CurrentTime: t.Add(24 * 30 * time.Hour), // 30 days
		DNSName:     dnsNames[0],
		Roots:       roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		log.Println("failed to verify certificate: " + err.Error())
		return false
	}

	return true
}

func fileExistAndIsNotEmpty(filename string) bool {
	file, err := os.Stat(filename)
	if err != nil {
		return false
	}
	if os.IsNotExist(err) {
		return false
	}
	if file.Size() == 0 {
		return false
	}
	return true
}

func isX509Format(b []byte) bool {
	block, _ := pem.Decode(b)
	if block == nil {
		return false
	}
	isKey := false
	isCert := false

	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		isKey = true
	}
	if _, err := x509.ParseCertificate(block.Bytes); err == nil {
		isCert = true
	}
	if !isKey && !isCert {
		return false
	}
	return true
}

// int32p returns an int32 pointer to the int32 value passed in
func int32p(x int32) *int32 {
	return &x
}

// stringp returns an string pointer to the string value passed in
func stringp(s string) *string {
	return &s
}

func (m Manager) createOrUpdateMutatingWebhookConfiguration() {

	mutatingWebhookConfigurationClient := m.clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
	_, err := mutatingWebhookConfigurationClient.Get(m.ctx, m.mutatingWebhookConfigurationName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			log.Panic(err)
		}

		// Create it
		caBundle, err := m.caBundle()
		if err != nil {
			log.Panic(err)
		}
		fail := addmissionregistrationv1.Fail
		none := addmissionregistrationv1.SideEffectClassNone
		mutatingWebhook := addmissionregistrationv1.MutatingWebhook{
			Name: fmt.Sprintf("%s.galleybytes.com", m.mutatingWebhookConfigurationName),
			ClientConfig: addmissionregistrationv1.WebhookClientConfig{
				CABundle: caBundle,
				Service: &addmissionregistrationv1.ServiceReference{
					Namespace: m.namespace,
					Name:      m.serviceName,
					Port:      int32p(443),
					Path:      stringp("/mutate"),
				},
			},
			AdmissionReviewVersions: []string{"v1"},
			TimeoutSeconds:          int32p(30),
			Rules: []addmissionregistrationv1.RuleWithOperations{
				{
					Operations: []addmissionregistrationv1.OperationType{addmissionregistrationv1.Create, addmissionregistrationv1.Update},
					Rule: addmissionregistrationv1.Rule{
						APIGroups:   []string{"tf.isaaguilar.com"},
						APIVersions: []string{"v1alpha2"},
						Resources:   []string{"terraforms"},
					},
				},
			},
			FailurePolicy: &fail,
			SideEffects:   &none,
		}
		mutatingWebhookConfiguration := addmissionregistrationv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: m.mutatingWebhookConfigurationName,
			},
			Webhooks: []addmissionregistrationv1.MutatingWebhook{
				mutatingWebhook,
			},
		}
		_, err = mutatingWebhookConfigurationClient.Create(m.ctx, &mutatingWebhookConfiguration, metav1.CreateOptions{})
		if err != nil {
			log.Panic(err)
		}
		log.Println("Created new mutating webhook configuration")

	}
}

func (m Manager) caBundle() ([]byte, error) {
	foundCACert := fileExistAndIsNotEmpty(m.caCertFilename)
	if !foundCACert {
		return []byte{}, fmt.Errorf("could not find '%s'", m.caCertFilename)
	}
	caCert, err := ioutil.ReadFile(m.caCertFilename)
	if err != nil {
		return []byte{}, err
	}
	return caCert, nil
}

func (m Manager) certMgmt() {
	recheckAfter := time.Duration(10 * time.Second)
	for {
		secret := m.GetOrCreateSecret()
		foundCAKey := fileExistAndIsNotEmpty(m.caKeyFilename)
		foundCACert := fileExistAndIsNotEmpty(m.caCertFilename)
		foundTLSKey := fileExistAndIsNotEmpty(m.tlsKeyFilename)
		foundTLSCert := fileExistAndIsNotEmpty(m.tlsCertFilename)
		if !foundCAKey || !foundCACert || !foundTLSKey || !foundTLSCert {
			log.Println("Waiting for certs to be mounted")
			recheckAfter = time.Duration(10 * time.Second)
			time.Sleep(recheckAfter)
			continue
		}

		caKey, err := ioutil.ReadFile(m.caKeyFilename)
		if err != nil {
			log.Panic(err)
		}
		caCert, err := ioutil.ReadFile(m.caCertFilename)
		if err != nil {
			log.Panic(err)
		}
		tlsCert, err := ioutil.ReadFile(m.tlsCertFilename)
		if err != nil {
			log.Panic(err)
		}
		tlsKey, err := ioutil.ReadFile(m.tlsKeyFilename)
		if err != nil {
			log.Panic(err)
		}

		if !isX509Format(caKey) {
			log.Printf("Failed to parse '%s'", m.caKeyFilename)
			recheckAfter = time.Duration(10 * time.Second)
			time.Sleep(recheckAfter)
			continue
		}
		if !isX509Format(caCert) {
			log.Printf("Failed to parse '%s'", m.caCertFilename)
			recheckAfter = time.Duration(10 * time.Second)
			time.Sleep(recheckAfter)
			continue
		}
		if !isX509Format(tlsKey) {
			log.Printf("Failed to parse '%s'", m.tlsKeyFilename)
			recheckAfter = time.Duration(10 * time.Second)
			time.Sleep(recheckAfter)
			continue
		}
		if !isX509Format(tlsCert) {
			log.Printf("Failed to parse '%s'", m.tlsCertFilename)
			recheckAfter = time.Duration(10 * time.Second)
			time.Sleep(recheckAfter)
			continue
		}

		selfSignedCert := &selfsigned.SelfSignedCert{
			Signer: selfsigned.Signer{
				CAKey:  caKey,
				CACert: caCert,
			},
			TLSCert: tlsCert,
			TLSKey:  tlsKey,
		}

		if string(secret.Data["ca.key"]) == string(caKey) &&
			string(secret.Data["ca.crt"]) == string(caCert) &&
			string(secret.Data["tls.key"]) == string(tlsKey) &&
			string(secret.Data["tls.crt"]) == string(tlsCert) {
			if isCertValid(caCert, tlsCert, m.dnsNames) {
				recheckAfter = time.Duration(24 * time.Hour)
				// recheckAfter = time.Duration(3 * time.Second)
				log.Printf("Cert validation passed. Will re-check in %s", recheckAfter.String())

				// Create or update the mutating webhook before starting the service
				m.createOrUpdateMutatingWebhookConfiguration()
				if !m.started {
					m.isReadyCh <- true
					m.started = true
				}
			} else {
				log.Printf("Certs are no longer valid. Updating secret '%s' with new certs\n", m.secretName)
				m.UpdateSecret(selfSignedCert)
				recheckAfter = time.Duration(10 * time.Second)
			}
		} else {
			log.Printf("Mounted certs do not match certs in 'secret/%s'. If this error continues, the pod may be misconfigured.\n", m.secretName)
			recheckAfter = time.Duration(10 * time.Second)
		}
		time.Sleep(recheckAfter)
	}
}

func genDNSNames(svc, ns string) []string {
	return []string{
		svc,
		fmt.Sprintf("%s.%s", svc, ns),
		fmt.Sprintf("%s.%s.svc", svc, ns),
		fmt.Sprintf("%s.%s.svc.cluster.local", svc, ns),
	}
}

func main() {
	getFlags()
	clientset := getClientOrDie(os.Getenv("KUBECONFIG"))
	mgr := Manager{
		ctx:                              context.TODO(),
		clientset:                        clientset,
		caKeyFilename:                    caKeyFilename,
		caCertFilename:                   caCertFilename,
		tlsKeyFilename:                   tlsKeyFilename,
		tlsCertFilename:                  tlsCertFilename,
		namespace:                        namespace,
		serviceName:                      serviceName,
		secretName:                       secretName,
		mutatingWebhookConfigurationName: mutatingWebhookConfigurationName,
		dnsNames:                         genDNSNames(serviceName, namespace),
		isReadyCh:                        make(chan bool),
	}
	go mgr.certMgmt()

	<-mgr.isReadyCh
	webserver.Run(tlsCertFilename, tlsKeyFilename, pluginMutationsFilename, apiServiceHost, apiUsername, apiPassword)
}
