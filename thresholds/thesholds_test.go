package thresholds

import (
	"testing"
	"time"

	executionv1 "github.com/secureCodeBox/secureCodeBox/operator/apis/execution/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetThreshholdForScan(t *testing.T) {
	t.Run("returns zero threshold for scans without deduplication annotation", func(t *testing.T) {
		scan := executionv1.Scan{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"irrelevant annotation": "...",
				},
			},
		}
		threshold, err := GetThreshholdForScan(scan)
		assert.Nil(t, err)
		assert.Equal(t, 0*time.Second, threshold)
	})

	t.Run("returns parsed threshold for scans with matching annotation", func(t *testing.T) {
		scan := executionv1.Scan{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"scan-deduplicator.securecodebox.io/min-time-interval": "24h",
				},
			},
		}
		threshold, err := GetThreshholdForScan(scan)
		assert.Nil(t, err)
		assert.Equal(t, 24*time.Hour, threshold)
	})

	t.Run("returns an error if the threshold is wrongly formatted", func(t *testing.T) {
		scan := executionv1.Scan{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"scan-deduplicator.securecodebox.io/min-time-interval": "invalid-time-format",
				},
			},
		}
		threshold, err := GetThreshholdForScan(scan)
		assert.EqualError(t, err, "error parsing duration: time: invalid duration \"invalid-time-format\"")
		assert.Equal(t, 0*time.Second, threshold)
	})

	t.Run("returns an error if the threshold is negative", func(t *testing.T) {
		scan := executionv1.Scan{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"scan-deduplicator.securecodebox.io/min-time-interval": "-24h",
				},
			},
		}
		threshold, err := GetThreshholdForScan(scan)
		assert.EqualError(t, err, "threshold must be a positive duration")
		assert.Equal(t, 0*time.Second, threshold)
	})
}
