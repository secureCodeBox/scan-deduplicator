package thresholds

import (
	"math"
	"time"

	executionv1 "github.com/secureCodeBox/secureCodeBox/operator/apis/execution/v1"
)

type ThreshholdRule struct {
	MatchLabels map[string]string
	Threshold   time.Duration
}

var rules []ThreshholdRule = []ThreshholdRule{
	// default fallback, no limitation
	{
		MatchLabels: map[string]string{},
		Threshold:   0 * time.Second,
	},
	{
		MatchLabels: map[string]string{
			"securecodebox.io/hook":                     "cascading-scans",
			"cascading.securecodebox.io/cascading-rule": "nmap-portscan",
		},
		Threshold: 4 * time.Hour,
	},
}

func GetThreshholdForScan(scan executionv1.Scan) time.Duration {
	highestMatchingThreshold := time.Duration(math.MaxInt64)
	for _, rule := range rules {
		if isMapSubset(rule.MatchLabels, scan.Labels) {
			if highestMatchingThreshold < rule.Threshold {
				highestMatchingThreshold = rule.Threshold
			}
		}
	}
	return highestMatchingThreshold
}

func isMapSubset[K, V comparable](m, sub map[K]V) bool {
	if len(sub) > len(m) {
		return false
	}
	for k, vsub := range sub {
		if vm, found := m[k]; !found || vm != vsub {
			return false
		}
	}
	return true
}
