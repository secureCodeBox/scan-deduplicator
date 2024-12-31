package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

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
)

type scanDeduplicatorValidator struct {
	logger                 kwhlog.Logger
	recentScansPerScanType map[string]map[uint64]time.Time
}

func (v *scanDeduplicatorValidator) Validate(_ context.Context, _ *kwhmodel.AdmissionReview, obj metav1.Object) (*kwhvalidating.ValidatorResult, error) {
	scan, ok := obj.(*executionv1.Scan)

	v.logger.Infof("Validating Scan.")

	if !ok {
		return nil, fmt.Errorf("not an scan")
	}

	var recentHashes map[uint64]time.Time
	if previousRecentHashes, ok := v.recentScansPerScanType[scan.Spec.ScanType]; ok {
		recentHashes = previousRecentHashes
	} else {
		v.logger.Infof("No recent hash lookup for scantype %s yet. Creating a new one", scan.Spec.ScanType)
		recentHashes = map[uint64]time.Time{}
		v.recentScansPerScanType[scan.Spec.ScanType] = recentHashes
	}

	hash, err := hashstructure.Hash(scan.Spec, hashstructure.FormatV2, nil)
	if err != nil {
		v.logger.Errorf("Failed to hash scan!", err)
		return &kwhvalidating.ValidatorResult{
			Valid:    true,
			Message:  "Failed to check for duplicated scan. Failed to generate scan hash",
			Warnings: []string{"Failed to generate scan hash.", "Deduplication wasn't performed."},
		}, err
	}

	if lastExecution, ok := recentHashes[hash]; ok {
		now := time.Now()
		threshhold := thresholds.GetThreshholdForScan(*scan)
		if lastExecution.Before(now.Add(-threshhold)) {
			v.logger.Infof("Scan was executed before (%v ago), but it was longer than %v. Starting it normally.", now.Sub(lastExecution), threshhold)
			recentHashes[hash] = now
			return &kwhvalidating.ValidatorResult{
				Valid:   true,
				Message: fmt.Sprintf("Scan was executed before (%v ago), but it was longer than %v. Starting it normally.", now.Sub(lastExecution), threshhold),
			}, nil
		} else {
			v.logger.Infof("it's last execution was too recent: %vago. Required min. threshold: %v", now, threshhold)
			return &kwhvalidating.ValidatorResult{
				Valid:   false,
				Message: fmt.Sprintf("it's last execution was too recent: %vago. Required min. threshold: %v", now.Sub(lastExecution), threshhold),
			}, nil
		}
	} else {
		recentHashes[hash] = time.Now()
		v.logger.Infof("Scan %s/%s(%d) hasn't been executed recently, it will be started normally.", scan.Namespace, scan.Name, hash)
		return &kwhvalidating.ValidatorResult{
			Valid:   true,
			Message: "Scan hasn't been executed recently, it will be started normally.",
		}, nil
	}
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

	vl := &scanDeduplicatorValidator{
		logger:                 logger,
		recentScansPerScanType: make(map[string]map[uint64]time.Time),
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
