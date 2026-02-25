# logstream-exporter

`logstream-exporter` is a Prometheus exporter for line-based log streams.

It receives log events over **TCP or UDP**, parses supported input formats (including **auto-detection**), extracts configured fields, and exposes them as Prometheus metrics on `/metrics`.

The project is designed for setups such as:

- `nginx -> syslog/syslog-ng -> logstream-exporter`
- direct JSON log streams
- RFC3164 syslog messages with JSON payloads

---

## Features

- **TCP and UDP** ingest (`server.log_transport`)
- **Prometheus** metrics endpoint
- **Config file + CLI overrides**
- **Automatic parser format detection** (`parser.format: auto`)
- Supports:
  - plain JSON log lines
  - RFC3164 syslog (`<PRI>Mon DD HH:MM:SS host tag: ...`)
  - syslog-ng JSON envelopes (`{"HOST":"...","PROGRAM":"...","MESSAGE":"..."}`)
- Nested JSON payload parsing (e.g. JSON in syslog `MESSAGE`)
- Configurable metric extraction (`metrics.definitions`)
- Configurable base event counter (`metrics.event_counter`)
- Structured logging (`text` or `json`)

---

## Supported Input Formats

The exporter can parse the following input styles:

1. **Plain JSON line**
   ```json
   {"status":"200","request_time":"0.012","bytes_sent":"1234","server_name":"grafana.example"}
   ```

2. **RFC3164 Syslog with JSON payload**
   ```text
   <190>Feb 25 12:00:00 nginxgw nginx: {"status":"200","request_time":"0.012","bytes_sent":"1234"}
   ```

3. **syslog-ng JSON envelope with nested JSON in `MESSAGE`**
   ```json
   {
     "HOST":"edge01",
     "PROGRAM":"nginx",
     "PRIORITY":"debug",
     "MESSAGE":"{\"status\":\"200\",\"request_time\":\"0.012\",\"bytes_sent\":\"1234\"}"
   }
   ```

---

## Build

The project is intended to be built on Linux via `Makefile`.

Typical commands:

```bash
make fmt
make vet
make test
make build
```

If your `Makefile` uses different targets, adapt accordingly.

---

## Run (Examples)

### With config file
```bash
./logstream-exporter -config config.example.yml
```

### With CLI overrides
```bash
./logstream-exporter \
  -config config.example.yml \
  -log-transport udp \
  -log-listen 127.0.0.1:2212 \
  -metrics-listen 127.0.0.1:9212 \
  -log-format auto \
  -payload-format json \
  -log-level info \
  -log-output text
```

### Print example configuration
```bash
./logstream-exporter -print-example-config
```

---

## CLI Parameters

The exporter supports configuration via YAML and CLI flags.
CLI flags override values from the config file.

### `-config`
Path to the YAML configuration file.

Example:
```bash
-config /etc/logstream-exporter/config.yml
```

---

### `-print-example-config`
Prints a valid example YAML config to stdout and exits.

Use this to bootstrap a new configuration.

---

### `-log-listen`
Listen address for the ingest socket (log stream input).

Examples:
- `127.0.0.1:2212`
- `0.0.0.0:2212`

---

### `-log-transport`
Ingest transport protocol.

Supported values:
- `tcp`
- `udp`

Use `udp` for common syslog setups. Use `tcp` for more reliable delivery.

---

### `-metrics-listen`
HTTP listen address for Prometheus metrics endpoint (`/metrics`).

Example:
- `127.0.0.1:9212`

---

### `-log-format`
Parser mode (top-level input parsing strategy).

Supported values:
- `auto`
- `json`
- `syslog_rfc3164`
- `syslog_ng_json`

This maps to `parser.format` in the config file.

---

### `-payload-format`
Payload parser format for syslog-based parsers.

Supported values:
- `json`
- `raw`

This maps to `parser.payload_format`.

---

### `-log-level`
Application log level.

Supported values:
- `debug`
- `info`
- `warn`
- `error`

---

### `-log-output`
Application log output format.

Supported values:
- `text`
- `json`

---

### `-event-labels`
Comma-separated label fields for the base event counter (`metrics.event_counter.labels`).

Example:
```bash
-event-labels status,request_method,server_name,syslog_host
```

This is useful for quick testing without editing YAML.

---

## Configuration File

## Example `config.yml`

```yaml
server:
  log_listen_address: "127.0.0.1:2212"
  log_transport: "udp"       # tcp | udp
  metrics_listen_address: "127.0.0.1:9212"
  read_timeout: "30s"
  line_max_bytes: 1048576

parser:
  format: "auto"            # auto | json | syslog_rfc3164 | syslog_ng_json
  payload_format: "json"    # json | raw (used for syslog-based payloads)

logging:
  level: "info"             # debug | info | warn | error
  format: "text"            # text | json

metrics:
  const_labels:
    app: "logstream-exporter"

  event_counter:
    name: "logstream_events_total"
    help: "Total processed log events."
    labels: ["status", "request_method", "server_name", "syslog_host", "syslog_tag", "geoip_country_code"]

  definitions:
    - name: "logstream_request_time_seconds"
      help: "Observed request_time values."
      field: "request_time"
      type: "histogram"
      labels: ["status", "request_method", "server_name", "syslog_host"]
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5]

    - name: "logstream_bytes_sent_total"
      help: "Accumulated bytes_sent values."
      field: "bytes_sent"
      type: "counter_add"
      labels: ["status", "server_name", "syslog_host"]

    - name: "logstream_upstream_response_time_seconds"
      help: "Observed upstream response time values."
      field: "upstream_response_time"
      type: "histogram"
      labels: ["status", "server_name", "syslog_host"]
      buckets: [0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5]
```

---

## Configuration Reference

### `server`
Controls ingest transport and metrics endpoint.

- `log_listen_address`: address for incoming logs
- `log_transport`: `tcp` or `udp`
- `metrics_listen_address`: Prometheus HTTP endpoint bind address
- `read_timeout`: socket read timeout (Go duration, e.g. `30s`)
- `line_max_bytes`: maximum accepted line/datagram size

**Recommendation**
- Use `udp` for classic syslog forwarding.
- Use `tcp` if loss is unacceptable and the sender supports TCP.
- Increase `line_max_bytes` if your JSON logs are large (e.g. long user agents, referers).

---

### `logging`
Controls exporter process logs (not parsed application logs).

- `level`: `debug|info|warn|error`
- `format`: `text|json`

**Recommendation**
- Use `debug` during integration.
- Use `info` in production.
- Use `json` if logs are collected by another log pipeline.

---

## Parser Configuration (Important)

The `parser` section defines **how incoming log lines are interpreted**.

```yaml
parser:
  format: "auto"
  payload_format: "json"
```

This is the most important part of the setup because transport (`tcp/udp`) and format (`json/syslog/...`) are independent.

---

### `parser.format`

Supported values:

- `auto`
- `json`
- `syslog_rfc3164`
- `syslog_ng_json`

---

### 1) `format: auto` (recommended for mixed environments)

The exporter tries to detect the format per line:

1. syslog-ng JSON envelope
2. plain JSON
3. RFC3164 syslog

#### Use when
- You have mixed sources
- You are migrating syslog-ng templates
- You are not fully sure which format arrives at the exporter
- You want the exporter to remain stable even if upstream format changes

#### Example
```yaml
parser:
  format: "auto"
  payload_format: "json"
```

#### Why it is often the best choice
This avoids configuration churn. It is especially useful when `syslog-ng` emits JSON envelopes for some sources and raw syslog for others.

---

### 2) `format: json`

The exporter expects each input line to be a **JSON object**.

#### Use when
- The sender already sends the final payload as a single JSON line
- `syslog-ng` is configured to forward only `MESSAGE` (and that message is JSON)
- You do not need syslog header/envelope fields

#### Example
```yaml
parser:
  format: "json"
```

#### Good fit for
- direct NGINX JSON log forwarding
- application logs already structured as JSON

#### Not a good fit for
- RFC3164 syslog lines
- syslog-ng JSON envelopes with nested JSON in `MESSAGE` (unless you only want envelope fields and do not need nested parsing)

---

### 3) `format: syslog_rfc3164`

The exporter expects classic RFC3164 syslog messages and parses the syslog envelope (`PRI`, timestamp, host, tag, pid, message).

`payload_format` controls how the `MSG` part is handled.

#### Use when
- You receive native syslog lines
- `syslog-ng` forwards raw syslog without `format-json`
- NGINX log payload is embedded in the syslog `MSG`

#### Example (JSON payload in syslog message)
```yaml
parser:
  format: "syslog_rfc3164"
  payload_format: "json"
```

#### Example (raw text payload in syslog message)
```yaml
parser:
  format: "syslog_rfc3164"
  payload_format: "raw"
```

#### Why `payload_format` matters
If the syslog message contains JSON (e.g. NGINX access log in JSON format), `payload_format: json` extracts fields like `status`, `request_time`, `bytes_sent`.
If the message is plain text, `payload_format: raw` avoids parse errors.

---

### 4) `format: syslog_ng_json`

The exporter expects a **syslog-ng JSON envelope** and parses the outer JSON. It then reads the `MESSAGE` field and handles it according to `payload_format`.

#### Use when
- `syslog-ng` sends `format-json(...)`
- The actual application log payload is stored in `MESSAGE`
- You want both syslog-ng envelope fields and nested payload fields

#### Example (common for NGINX via syslog-ng)
```yaml
parser:
  format: "syslog_ng_json"
  payload_format: "json"
```

#### Example (mixed plain-text messages)
```yaml
parser:
  format: "syslog_ng_json"
  payload_format: "raw"
```

#### Why this is useful
It preserves envelope metadata like:

- `HOST`
- `PROGRAM`
- `PRIORITY`
- `FACILITY`
- `SOURCEIP`

while still extracting metrics from nested JSON payloads.

---

### `parser.payload_format`

Supported values:
- `json`
- `raw`

This setting is used by syslog-based parsers (`syslog_rfc3164`, `syslog_ng_json`) and by `auto` when it resolves to one of those.

#### `payload_format: json`
Parse nested message payload as JSON.

Use when the syslog message contains something like:
```json
{"status":"200","request_time":"0.012","bytes_sent":"1234"}
```

#### `payload_format: raw`
Do not parse nested payload. Keep it as text only.

Use when the syslog `MESSAGE` is plain text (e.g. DHCP/system logs) and you only want envelope-level metadata.

---

### Parser Selection Guidance

#### A) Direct NGINX JSON stream
```yaml
parser:
  format: "json"
```
**Reason:** fastest and simplest; no envelope parsing needed.

---

#### B) Native syslog from NGINX / syslog relay (RFC3164 + JSON message)
```yaml
parser:
  format: "syslog_rfc3164"
  payload_format: "json"
```
**Reason:** parse syslog headers and the nested NGINX JSON payload.

---

#### C) syslog-ng JSON envelope with nested NGINX JSON
```yaml
parser:
  format: "syslog_ng_json"
  payload_format: "json"
```
**Reason:** exact parser for the syslog-ng `format-json` output.

---

#### D) Unknown / changing environment (recommended during rollout)
```yaml
parser:
  format: "auto"
  payload_format: "json"
```
**Reason:** best operational flexibility; detects multiple formats automatically.

---

## Metrics Configuration

The `metrics` section defines:

- static labels (`const_labels`)
- a base event counter (`event_counter`)
- extracted metrics (`definitions`)

---

### `metrics.const_labels`

Static labels added to all exporter-defined metrics.

Example:
```yaml
metrics:
  const_labels:
    app: "logstream-exporter"
    environment: "prod"
```

#### Use when
- you want stable context labels without repeating them in every metric definition
- you scrape multiple exporter instances and want to distinguish them consistently

---

## `metrics.event_counter` (Important)

This is the base counter that increments for every successfully parsed event.

Example:
```yaml
metrics:
  event_counter:
    name: "logstream_events_total"
    help: "Total processed log events."
    labels: ["status", "request_method", "server_name", "syslog_host", "syslog_tag"]
```

---

### Fields

#### `name`
Prometheus metric name for the event counter.

- Must be a valid Prometheus metric name.
- Typical pattern: `<app>_events_total`

#### `help`
Prometheus help text.

Keep it short and precise.

#### `labels`
List of field names to extract from the parsed record and use as labels.

These fields may come from:
- the payload JSON (e.g. `status`, `request_method`, `server_name`)
- RFC3164 syslog parsing (e.g. `syslog_host`, `syslog_tag`)
- syslog-ng envelope parsing (e.g. `PROGRAM`, `HOST`, or normalized aliases like `syslog_host`)

---

### Why `metrics.event_counter` is useful

This metric gives you:
- event throughput
- event distribution by status / method / host
- a quick validation that parsing works (counter increases)
- a cheap baseline metric even before adding detailed definitions

---

### Recommended label strategy for `event_counter`

Prefer **low-cardinality** labels:

Good:
- `status`
- `request_method`
- `server_name`
- `geoip_country_code`
- `syslog_host`
- `syslog_tag`

Avoid high-cardinality labels:
- `request_uri` (can explode)
- `remote_addr`
- `http_user_agent`
- `request_id`
- `msec`

High-cardinality labels increase memory usage and can harm Prometheus performance.

---

### Example `event_counter` setups

#### Minimal (safe default)
```yaml
metrics:
  event_counter:
    name: "logstream_events_total"
    help: "Total processed log events."
    labels: ["status", "request_method", "server_name"]
```

#### Syslog-aware
```yaml
metrics:
  event_counter:
    name: "logstream_events_total"
    help: "Total processed log events."
    labels: ["status", "request_method", "server_name", "syslog_host", "syslog_tag"]
```

#### Security/edge overview
```yaml
metrics:
  event_counter:
    name: "logstream_events_total"
    help: "Total processed log events."
    labels: ["status", "server_name", "geoip_country_code"]
```

---

## `metrics.definitions` (Important)

This section defines **field-to-metric extraction rules**.

Each definition reads one parsed field (e.g. `request_time`) and updates one Prometheus metric.

Example:
```yaml
metrics:
  definitions:
    - name: "logstream_request_time_seconds"
      help: "Observed request_time values."
      field: "request_time"
      type: "histogram"
      labels: ["status", "request_method", "server_name"]
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5]
```

---

### Fields

#### `name`
Prometheus metric name.

Examples:
- `logstream_request_time_seconds`
- `logstream_bytes_sent_total`
- `logstream_upstream_response_time_seconds`

#### `help`
Prometheus help string.

#### `field`
Name of the parsed record field to read (string value expected, parsed as numeric where required).

Examples:
- `request_time`
- `bytes_sent`
- `upstream_response_time`
- `body_bytes_sent`

#### `type`
Metric behavior.

Supported:
- `counter_add`
- `gauge_set`
- `histogram`

#### `labels`
Labels for this metric (same cardinality considerations as above).

#### `buckets` (only for `histogram`)
Prometheus histogram buckets.

If omitted for histograms, default buckets are applied by the exporter config validation.

---

### Metric Types Explained

### `counter_add`
Adds the numeric field value to a Prometheus counter.

#### Best for
Monotonic accumulation from per-event values, e.g.:
- `bytes_sent`
- `body_bytes_sent`

#### Example
```yaml
- name: "logstream_bytes_sent_total"
  help: "Accumulated bytes_sent values."
  field: "bytes_sent"
  type: "counter_add"
  labels: ["status", "server_name"]
```

**Why this is useful:**
You can derive traffic volume per vhost/status and rates over time using `rate()`.

---

### `gauge_set`
Sets the metric to the latest numeric field value.

#### Best for
Instant values in logs (less common for access logs, more common for state logs).

Examples:
- queue depth
- active connections (if logged)
- application internal state snapshots

#### Example
```yaml
- name: "logstream_upstream_length_bytes"
  help: "Last observed upstream_response_length."
  field: "upstream_response_length"
  type: "gauge_set"
  labels: ["server_name"]
```

**Why this is useful:**
Tracks the latest observed value per label set, not an accumulation.

---

### `histogram`
Observes each numeric value into a histogram bucket distribution.

#### Best for
Latency and duration fields:
- `request_time`
- `upstream_connect_time`
- `upstream_header_time`
- `upstream_response_time`

#### Example
```yaml
- name: "logstream_request_time_seconds"
  help: "Observed request_time values."
  field: "request_time"
  type: "histogram"
  labels: ["status", "request_method", "server_name"]
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5]
```

**Why this is useful:**
You can compute percentiles (via Prometheus histogram functions) and identify latency regressions.

---

## Recommended `metrics.definitions` for NGINX Access Logs

### Latency metrics
```yaml
- name: "logstream_request_time_seconds"
  help: "Observed request_time values."
  field: "request_time"
  type: "histogram"
  labels: ["status", "request_method", "server_name"]
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5]

- name: "logstream_upstream_response_time_seconds"
  help: "Observed upstream response time values."
  field: "upstream_response_time"
  type: "histogram"
  labels: ["status", "server_name"]
  buckets: [0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5]
```

### Traffic volume
```yaml
- name: "logstream_bytes_sent_total"
  help: "Accumulated bytes_sent values."
  field: "bytes_sent"
  type: "counter_add"
  labels: ["status", "server_name"]
```

### Optional upstream payload size
```yaml
- name: "logstream_upstream_response_length_bytes_total"
  help: "Accumulated upstream response length."
  field: "upstream_response_length"
  type: "counter_add"
  labels: ["status", "server_name"]
```

---

## Choosing Labels for `metrics.definitions`

The same cardinality rule applies here.

### Good labels
- `status`
- `request_method`
- `server_name`
- `syslog_host`
- `geoip_country_code` (usually acceptable)

### Risky labels (high cardinality)
- `request_uri`
- `remote_addr`
- `request_id`
- `http_user_agent`
- `http_referer`

Use high-cardinality labels only if you explicitly accept the Prometheus memory cost.

---

## Practical Parser + Metrics Examples

### 1) NGINX JSON via syslog-ng JSON envelope (your current setup)
```yaml
server:
  log_transport: "udp"

parser:
  format: "auto"
  payload_format: "json"

metrics:
  event_counter:
    name: "logstream_events_total"
    help: "Total processed log events."
    labels: ["status", "request_method", "server_name", "syslog_host", "syslog_tag"]

  definitions:
    - name: "logstream_request_time_seconds"
      help: "Observed request_time values."
      field: "request_time"
      type: "histogram"
      labels: ["status", "server_name"]
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5]
```

**Why this is sensible:**
`auto` handles syslog-ng envelope safely, `payload_format: json` extracts NGINX fields from `MESSAGE`, and labels remain low-cardinality.

---

### 2) Native RFC3164 syslog only
```yaml
parser:
  format: "syslog_rfc3164"
  payload_format: "json"
```

**Why this is sensible:**
No auto-detection overhead and strict parsing if your upstream format is controlled and stable.

---

### 3) Plain JSON direct stream
```yaml
parser:
  format: "json"
```

**Why this is sensible:**
Minimal parsing path; best performance and simplest configuration.

---

## Debugging / Troubleshooting

### Symptom: `failed to parse line` + RFC3164 error for JSON input
Cause: parser is set to `syslog_rfc3164`, but input is JSON (or syslog-ng JSON envelope).

Fix:
```yaml
parser:
  format: "auto"
  payload_format: "json"
```

---

### Symptom: events are counted, but no NGINX metrics appear
Cause: top-level parse works, but nested `MESSAGE` payload is not parsed as JSON.

Fix:
- use `payload_format: json`
- and use `format: auto`, `syslog_rfc3164`, or `syslog_ng_json` depending on input

---

### Symptom: Prometheus memory usage grows unexpectedly
Cause: high-cardinality labels (e.g. `request_uri`, `remote_addr`, `request_id`).

Fix:
- remove or reduce high-cardinality labels
- keep `event_counter.labels` and metric labels compact

---

## Operational Notes

- Prefer `parser.format: auto` during integration and migration.
- Prefer `parser.format: json` or `syslog_rfc3164` in tightly controlled environments if you want stricter behavior.
- Keep `metrics.event_counter` label set small and stable.
- Start with 2–3 `metrics.definitions`, then expand based on observability needs.
- Use `debug` logging during rollout, then switch to `info` in production.

---

## Author and License

- Bodo Schulz

## License

[Apache](LICENSE)
