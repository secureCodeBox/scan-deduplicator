package thresholds

import (
	"fmt"
	"time"

	executionv1 "github.com/secureCodeBox/secureCodeBox/operator/apis/execution/v1"
)

func GetThreshholdForScan(scan executionv1.Scan) (time.Duration, error) {
	thresholdStr, ok := scan.Annotations["scan-deduplicator.securecodebox.io/min-time-interval"]
	if !ok {
		return 0 * time.Second, nil
	}

	threshold, err := time.ParseDuration(thresholdStr)
	if err != nil {
		return 0, fmt.Errorf("error parsing duration: %w", err)
	}

	if threshold < 0 {
		return 0, fmt.Errorf("threshold must be a positive duration")
	}

	return threshold, nil
}
