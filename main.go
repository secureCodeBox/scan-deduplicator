package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/secureCodeBox/scan-deduplicator/thresholds"
	executionv1 "github.com/secureCodeBox/secureCodeBox/operator/apis/execution/v1"
	"github.com/sirupsen/logrus"
	kwhhttp "github.com/slok/kubewebhook/v2/pkg/http"
	kwhlog "github.com/slok/kubewebhook/v2/pkg/log"
	kwhlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	kwhmodel "github.com/slok/kubewebhook/v2/pkg/model"
	kwhvalidating "github.com/slok/kubewebhook/v2/pkg/webhook/validating"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/valkey-io/valkey-go"
)

type scanDeduplicatorValidator struct {
	logger      kwhlog.Logger
	cacheClient *valkey.Client
}

func (v *scanDeduplicatorValidator) Validate(ctx context.Context, _ *kwhmodel.AdmissionReview, obj metav1.Object) (*kwhvalidating.ValidatorResult, error) {
	v.logger.Infof("Validating Scan.")
	scan, ok := obj.(*executionv1.Scan)

	if !ok {
		return nil, fmt.Errorf("not an scan")
	}

	client := *v.cacheClient

	hash, err := hashstructure.Hash(scan.Spec, hashstructure.FormatV2, nil)
	if err != nil {
		v.logger.Errorf("Failed to hash scan!", err)
		return &kwhvalidating.ValidatorResult{
			Valid:    true,
			Message:  "Failed to check for duplicated scan. Failed to generate scan hash",
			Warnings: []string{"Failed to generate scan hash.", "Deduplication wasn't performed."},
		}, err
	}

	threshhold, err := thresholds.GetThreshholdForScan(*scan)
	if err != nil {
		v.logger.Errorf("Failed to get threshold for scan!", err)
		return &kwhvalidating.ValidatorResult{
			Valid:    true,
			Message:  fmt.Sprintf("Failed to get threshold for scan. %s", err),
			Warnings: []string{"Failed to get threshold for scan.", "Deduplication wasn't performed."},
		}, err
	}

	if threshhold == 0 {
		v.logger.Infof("No deduplication threshold set. Skipping deduplication.")
		return &kwhvalidating.ValidatorResult{
			Valid:   true,
			Message: "No deduplication threshold set. Skipping deduplication.",
		}, nil
	}

	res, err := client.Do(ctx, client.B().Exists().Key(fmt.Sprintf("ns/%s/scan/%d", obj.GetNamespace(), hash)).Build()).ToInt64()

	if err != nil {
		v.logger.Errorf("Failed to check for duplicated scan!", err)
		return &kwhvalidating.ValidatorResult{
			Valid:    true,
			Message:  fmt.Sprintf("Failed to check for duplicated scan. %s", err),
			Warnings: []string{"Failed to check for duplicated scan. Could not reach cache.", "Deduplication wasn't performed."},
		}, err
	}

	if res == 1 {
		v.logger.Infof("it's last execution was too recent. Required min. threshold: %v", threshhold)
		return &kwhvalidating.ValidatorResult{
			Valid:   false,
			Message: fmt.Sprintf("it's last execution was too recent. Required min. threshold: %v", threshhold),
		}, nil
	}

	v.logger.Infof("Setting cache key for scan %s. Threshold: %v", fmt.Sprintf("ns/%s/scan/%d", obj.GetNamespace(), hash), threshhold)
	err = client.Do(ctx, client.B().Set().Key(fmt.Sprintf("ns/%s/scan/%d", obj.GetNamespace(), hash)).Value("").Nx().Ex(threshhold).Build()).Error()
	if err != nil {
		v.logger.Errorf("Failed to set cache key!", err)
		return &kwhvalidating.ValidatorResult{
			Valid:    false,
			Message:  fmt.Sprintf("Failed to set cache key. %s", err),
			Warnings: []string{"Failed to set cache key. It was potentially already started by a parralel threat.", "Blocking execution."},
		}, err
	}

	v.logger.Infof("Permitting scan, it was not executed inside the threshold.")
	return &kwhvalidating.ValidatorResult{
		Valid:   true,
		Message: "Permitting scan, it was not executed inside the threshold.",
	}, nil
}

type config struct {
	certFile string
	keyFile  string
	addr     string
}

func initFlags() *config {
	cfg := &config{}

	fl := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fl.StringVar(&cfg.certFile, "tls-cert-file", "", "TLS certificate file")
	fl.StringVar(&cfg.keyFile, "tls-key-file", "", "TLS key file")
	fl.StringVar(&cfg.addr, "listen-addr", ":8080", "The address to start the server")

	_ = fl.Parse(os.Args[1:])
	return cfg
}

func main() {
	logrusLogEntry := logrus.NewEntry(logrus.New())
	logrusLogEntry.Logger.SetLevel(logrus.DebugLevel)
	logger := kwhlogrus.NewLogrus(logrusLogEntry)

	logger.Infof("Parsing Flags")
	cfg := initFlags()

	valkeyPassword, ok := os.LookupEnv("VALKEY_PASSWORD")
	if !ok {
		logger.Errorf("VALKEY_PASSWORD not set")
		os.Exit(1)
	}

	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{"scan-deduplicator-cache:6379"}, Password: valkeyPassword})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	vl := &scanDeduplicatorValidator{
		logger:      logger,
		cacheClient: &client,
	}

	logger.Infof("Initializing Webhook")
	vcfg := kwhvalidating.WebhookConfig{
		ID:        "scanDeduplicatorValidator",
		Obj:       &executionv1.Scan{},
		Validator: vl,
		Logger:    logger,
	}
	wh, err := kwhvalidating.NewWebhook(vcfg)
	if err != nil {
		logger.Errorf("error creating webhook: %s", err)
		os.Exit(1)
	}
	logger.Infof("Initialized Webhook")

	// Serve the webhook.
	logger.Infof("Listening on %s", cfg.addr)
	err = http.ListenAndServeTLS(cfg.addr, cfg.certFile, cfg.keyFile, kwhhttp.MustHandlerFor(kwhhttp.HandlerConfig{
		Webhook: wh,
		Logger:  logger,
	}))
	if err != nil {
		logger.Errorf("error serving webhook: %s", err)
		os.Exit(1)
	}

	logger.Infof("Exiting")
}
