package thresholds

import (
	"testing"
	"time"

	executionv1 "github.com/secureCodeBox/secureCodeBox/operator/apis/execution/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetThreshholdForScan(t *testing.T) {
	t.Run("returns zero threshold for scans without matching labels", func(t *testing.T) {
		scan := executionv1.Scan{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}
		threshold := GetThreshholdForScan(scan)
		assert.Equal(t, 0*time.Second, threshold)
	})

	t.Run("returns matchign thresholds for scnas with matching rules threshold for scans without matching labels", func(t *testing.T) {
		scan := executionv1.Scan{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"securecodebox.io/hook":                     "cascading-scans",
					"cascading.securecodebox.io/cascading-rule": "nmap-portscan",
					"foo": "bar",
				},
			},
		}
		threshold := GetThreshholdForScan(scan)
		assert.Equal(t, 4*time.Hour, threshold)
	})
}
