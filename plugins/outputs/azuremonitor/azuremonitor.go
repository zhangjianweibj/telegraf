package azuremonitor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/metric"
	"github.com/influxdata/telegraf/plugins/outputs"
)

// AzureMonitor allows publishing of metrics to the Azure Monitor custom metrics service
type AzureMonitor struct {
	useMsi              bool              `toml:"use_managed_service_identity"`
	ResourceID          string            `toml:"resource_id"`
	Region              string            `toml:"region"`
	Timeout             internal.Duration `toml:"Timeout"`
	AzureSubscriptionID string            `toml:"azure_subscription"`
	AzureTenantID       string            `toml:"azure_tenant"`
	AzureClientID       string            `toml:"azure_client_id"`
	AzureClientSecret   string            `toml:"azure_client_secret"`
	StringAsDimension   bool              `toml:"string_as_dimension"`

	msiToken    *msiToken
	oauthConfig *adal.OAuthConfig
	adalToken   adal.OAuthTokenProvider

	client *http.Client

	cache map[time.Time]map[uint64]*aggregate
}

var sampleConfig = `
  ## The resource ID against which metric will be logged.  If not
  ## specified, the plugin will attempt to retrieve the resource ID
  ## of the VM via the instance metadata service (optional if running 
  ## on an Azure VM with MSI)
  #resource_id = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.Compute/virtualMachines/<vm-name>"
  ## Azure region to publish metrics against.  Defaults to eastus.
  ## Leave blank to automatically query the region via MSI.
  #region = "useast"

  ## Write HTTP timeout, formatted as a string.  If not provided, will default
  ## to 5s. 0s means no timeout (not recommended).
  # timeout = "5s"

  ## Whether or not to use managed service identity.
  #use_managed_service_identity = true

  ## Fill in the following values if using Active Directory Service
  ## Principal or User Principal for authentication.
  ## Subscription ID
  #azure_subscription = ""
  ## Tenant ID
  #azure_tenant = ""
  ## Client ID
  #azure_client_id = ""
  ## Client secrete
  #azure_client_secret = ""
`

const (
	defaultRegion string = "eastus"

	defaultMSIResource string = "https://monitoring.azure.com/"

	metricsURLTemplate string = "https://%s.monitoring.azure.com%s/metrics"
)

var _ telegraf.AggregatingOutput = (*AzureMonitor)(nil)

// Connect initializes the plugin and validates connectivity
func (a *AzureMonitor) Connect() error {
	// Set defaults

	// If no direct AD values provided, fall back to MSI
	if a.AzureSubscriptionID == "" && a.AzureTenantID == "" && a.AzureClientID == "" && a.AzureClientSecret == "" {
		a.useMsi = true
	} else if a.AzureSubscriptionID == "" || a.AzureTenantID == "" || a.AzureClientID == "" || a.AzureClientSecret == "" {
		return fmt.Errorf("Must provide values for azureSubscription, azureTenant, azureClient and azureClientSecret, or leave all blank to default to MSI")
	}

	if !a.useMsi {
		// If using direct AD authentication create the AD access client
		oauthConfig, err := adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, a.AzureTenantID)
		if err != nil {
			return fmt.Errorf("Could not initialize AD client: %s", err)
		}
		a.oauthConfig = oauthConfig
	}

	// Validate the resource identifier
	metadata, err := a.GetInstanceMetadata()
	if err != nil {
		return fmt.Errorf("No resource id specified, and Azure Instance metadata service not available.  If not running on an Azure VM, provide a value for resourceId")
	}
	a.ResourceID = metadata.AzureResourceID

	if a.Region == "" {
		a.Region = metadata.Compute.Location
	}

	a.client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
		Timeout: a.Timeout.Duration,
	}

	// Validate credentials
	err = a.validateCredentials()
	if err != nil {
		return err
	}

	a.Reset()

	return nil
}

func (a *AzureMonitor) validateCredentials() error {
	if a.useMsi {
		// Check expiry on the token
		if a.msiToken == nil || a.msiToken.ExpiresInDuration() < time.Minute {
			msiToken, err := a.getMsiToken(a.AzureClientID, defaultMSIResource)
			if err != nil {
				return err
			}
			log.Printf("Bearer token acquired; expiring in %s\n", msiToken.ExpiresInDuration().String())
			a.msiToken = msiToken
		}
		return nil
	}

	adToken, err := adal.NewServicePrincipalToken(
		*(a.oauthConfig), a.AzureClientID, a.AzureClientSecret,
		azure.PublicCloud.ActiveDirectoryEndpoint)
	if err != nil {
		return fmt.Errorf("Could not acquire ADAL token: %s", err)
	}
	a.adalToken = adToken
	return nil
}

// Description provides a description of the plugin
func (a *AzureMonitor) Description() string {
	return "Configuration for sending aggregate metrics to Azure Monitor"
}

// SampleConfig provides a sample configuration for the plugin
func (a *AzureMonitor) SampleConfig() string {
	return sampleConfig
}

// Close shuts down an any active connections
func (a *AzureMonitor) Close() error {
	return nil
}

type azureMonitorMetric struct {
	Time time.Time         `json:"time"`
	Data *azureMonitorData `json:"data"`
}

type azureMonitorData struct {
	BaseData *azureMonitorBaseData `json:"baseData"`
}

type azureMonitorBaseData struct {
	Metric         string                `json:"metric"`
	Namespace      string                `json:"namespace"`
	DimensionNames []string              `json:"dimNames"`
	Series         []*azureMonitorSeries `json:"series"`
}

type azureMonitorSeries struct {
	DimensionValues []string `json:"dimValues"`
	Min             float64  `json:"min"`
	Max             float64  `json:"max"`
	Sum             float64  `json:"sum"`
	Count           float64  `json:"count"`
}

// Write writes metrics to the remote endpoint
func (a *AzureMonitor) Write(metrics []telegraf.Metric) error {
	var azmetrics map[uint64]*azureMonitorMetric
	for _, m := range metrics {
		id := hashIDWithTagKeysOnly(m)
		if azm, ok := azmetrics[id]; !ok {
			azmetrics[id] = translate(m)
		} else {
			azmetrics[id].Data.BaseData.Series = append(
				azm.Data.BaseData.Series,
				translate(m).Data.BaseData.Series...,
			)
		}
	}

	var body []byte
	for _, m := range metrics {
		// Azure Monitor accepts new batches of points in new-line delimited
		// JSON, following RFC 4288.
		jsonBytes, err := json.Marshal(&m)
		if err != nil {
			log.Printf("Error marshalling metrics %s", err)
			return nil
		}
		body = append(body, jsonBytes...)
		body = append(body, '\n')
	}

	if err := a.validateCredentials(); err != nil {
		return fmt.Errorf("Error authenticating: %v", err)
	}

	metricsEndpoint := fmt.Sprintf(metricsURLTemplate,
		a.Region, a.ResourceID)

	req, err := http.NewRequest("POST", metricsEndpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+a.msiToken.AccessToken)
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode >= 300 || resp.StatusCode < 200 {
		var reply []byte
		reply, err = ioutil.ReadAll(resp.Body)

		if err != nil {
			reply = nil
		}
		return fmt.Errorf("Post Error. HTTP response code:%d message:%s reply:\n%s",
			resp.StatusCode, resp.Status, reply)
	}

	return nil
}

func hashIDWithTagKeysOnly(m telegraf.Metric) uint64 {
	h := fnv.New64a()
	h.Write([]byte(m.Name()))
	h.Write([]byte("\n"))
	for _, tag := range m.TagList() {
		h.Write([]byte(tag.Key))
		h.Write([]byte("\n"))
	}
	b := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(b, uint64(m.Time().UnixNano()))
	h.Write(b[:n])
	h.Write([]byte("\n"))
	return h.Sum64()
}

func translate(metric telegraf.Metric) *azureMonitorMetric {
	var dimensionNames []string
	var dimensionValues []string
	for i, tag := range metric.TagList() {
		// Azure custom metrics service supports up to 10 dimensions
		if i > 10 {
			log.Printf("W! [outputs.azuremonitor] metric [%s] exceeds 10 dimensions", metric.Name())
			continue
		}
		dimensionNames = append(dimensionNames, tag.Key)
		dimensionValues = append(dimensionValues, tag.Value)
	}

	min, _ := metric.GetField("min")
	max, _ := metric.GetField("max")
	sum, _ := metric.GetField("sum")
	count, _ := metric.GetField("count")
	return &azureMonitorMetric{
		Time: metric.Time(),
		Data: &azureMonitorData{
			BaseData: &azureMonitorBaseData{
				Metric:         metric.Name(),
				Namespace:      "default",
				DimensionNames: dimensionNames,
				Series: []*azureMonitorSeries{
					&azureMonitorSeries{
						DimensionValues: dimensionValues,
						Min:             min.(float64),
						Max:             max.(float64),
						Sum:             sum.(float64),
						Count:           count.(float64),
					},
				},
			},
		},
	}
}

type aggregate struct {
	m       telegraf.Metric
	updated bool
}

// Add will append a metric to the output aggregate
func (a *AzureMonitor) Add(m telegraf.Metric) {
	// Azure Monitor only supports aggregates 30 minutes into the past
	// and 4 minutes into the future. Future metrics are dropped when written.
	t := m.Time()
	tbucket := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, t.Location())
	if tbucket.After(time.Now().Truncate(time.Minute * 30)) {
		// TODO(gunnar): log metric is too late to fit within the aggregation window
		return
	}

	// Azure Monitor doesn't have a string value type, so convert string
	// fields to dimensions (a.k.a. tags) if enabled.
	if a.StringAsDimension {
		for fk, fv := range m.Fields() {
			if v, ok := fv.(string); ok {
				m.AddTag(fk, v)
			}
		}
	}

	for _, f := range m.FieldList() {
		fv, ok := convert(f.Value)
		if !ok {
			continue
		}

		// Azure Monitor does not support fields so the field
		// name is appended to the metric name.
		name := m.Name() + "_" + sanitize(f.Key)
		id := hashIDWithField(m.HashID(), f.Key)

		_, ok = a.cache[tbucket]
		if !ok {
			// Time bucket does not exist and needs to be created.
			a.cache[tbucket] = make(map[uint64]*aggregate)
			a.cache[tbucket][id] = &aggregate{
				m:       newAggMetric(name, m.Tags(), fv, tbucket),
				updated: true,
			}
			continue
		}

		agg, ok := a.cache[tbucket][id]
		if !ok {
			// Aggregate metric does not exist and needs to be created.
			a.cache[tbucket][id] = &aggregate{
				m:       newAggMetric(name, m.Tags(), fv, tbucket),
				updated: true,
			}
			continue
		}

		// Add new value to existing aggregate metric
		for _, tf := range agg.m.FieldList() {
			tfv := tf.Value.(float64)
			switch tf.Key {
			case "min":
				if fv < tfv {
					agg.m.AddField("min", fv)
				}
			case "max":
				if fv > tfv {
					agg.m.AddField("max", fv)
				}
			case "sum":
				agg.m.AddField("sum", tfv+fv)
			case "count":
				agg.m.AddField("count", tfv+1)
			}
		}
		agg.updated = true
		a.cache[tbucket][id] = agg
	}
}

func convert(in interface{}) (float64, bool) {
	switch v := in.(type) {
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float64:
		return v, true
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

var invalidNameCharRE = regexp.MustCompile(`[^a-zA-Z0-9_]`)

func sanitize(value string) string {
	return invalidNameCharRE.ReplaceAllString(value, "_")
}

func newAggMetric(name string, tags map[string]string, fv float64, t time.Time) telegraf.Metric {
	nm, _ := metric.New(
		name,
		tags,
		map[string]interface{}{
			"min":   fv,
			"max":   fv,
			"sum":   fv,
			"count": 1,
		},
		t,
	)
	return nm
}

func hashIDWithField(id uint64, fk string) uint64 {
	h := fnv.New64a()
	b := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(b, id)
	h.Write(b[:n])
	h.Write([]byte("\n"))
	h.Write([]byte(fk))
	h.Write([]byte("\n"))
	return h.Sum64()
}

// Push sends metrics to the output metric buffer
func (a *AzureMonitor) Push() []telegraf.Metric {
	var metrics []telegraf.Metric
	for _, aggs := range a.cache {
		for _, agg := range aggs {
			// Only send aggregates that have had an update since
			// the last push.
			if !agg.updated {
				continue
			}
			metrics = append(metrics, agg.m)
		}
	}
	return metrics
}

// Reset clears the cache of aggregate metrics
func (a *AzureMonitor) Reset() {
	for tbucket := range a.cache {
		// Remove aggregates older than 30 minutes
		if tbucket.After(time.Now().Truncate(time.Minute * 30)) {
			delete(a.cache, tbucket)
			continue
		}
		for id := range a.cache[tbucket] {
			a.cache[tbucket][id].updated = false
		}
	}
}

func init() {
	outputs.Add("azuremonitor", func() telegraf.Output {
		return &AzureMonitor{
			StringAsDimension: true,
			Timeout:           internal.Duration{Duration: time.Second * 5},
			Region:            defaultRegion,
		}
	})
}
