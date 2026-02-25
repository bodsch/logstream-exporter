// Package parser defines log line parsers and parser compositions for JSON, RFC3164 syslog,
// and syslog-ng JSON envelopes with optional nested payload parsing.
package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Record is a normalized parsed log event.
type Record map[string]string

// Parser parses one raw log line into a normalized record.
type Parser interface {
	// ParseLine parses one line of input.
	ParseLine(line []byte) (Record, error)
	// Format returns the configured parser format name.
	Format() string
}

const (
	// MetaInputFormatKey stores the actually detected/used top-level input format.
	MetaInputFormatKey = "_meta_input_format"
	// MetaPayloadFormatKey stores the configured/used nested payload format.
	MetaPayloadFormatKey = "_meta_payload_format"
	// MetaParserKey stores the parser mode used by the application (e.g. auto).
	MetaParserKey = "_meta_parser"
)

var (
	// ErrNotSyslogNGJSONEnvelope indicates that a JSON line is valid JSON but does not match
	// the expected syslog-ng envelope structure.
	ErrNotSyslogNGJSONEnvelope = errors.New("line is not a syslog-ng json envelope")
)

// JSONParser parses line-delimited JSON objects.
type JSONParser struct{}

// NewJSONParser creates a JSON line parser instance.
func NewJSONParser() *JSONParser {
	return &JSONParser{}
}

// Format returns the parser format identifier.
func (p *JSONParser) Format() string {
	return "json"
}

// ParseLine parses a JSON object and converts all top-level values to strings.
func (p *JSONParser) ParseLine(line []byte) (Record, error) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty line")
	}

	if trimmed[0] != '{' {
		return nil, fmt.Errorf("json parser expects an object starting with '{'")
	}

	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}

	record := make(Record, len(raw))
	for key, value := range raw {
		record[key] = toString(value)
	}

	return record, nil
}

// SyslogNGJSONEnvelopeParser parses syslog-ng JSON envelopes and optionally parses the
// nested MESSAGE field as JSON.
type SyslogNGJSONEnvelopeParser struct {
	payloadFormat string
	jsonParser    *JSONParser
	messageField  string
}

// NewSyslogNGJSONEnvelopeParser creates a parser for syslog-ng JSON envelope messages.
// Supported payload formats are "json" and "raw".
func NewSyslogNGJSONEnvelopeParser(payloadFormat string) (*SyslogNGJSONEnvelopeParser, error) {
	format := strings.ToLower(strings.TrimSpace(payloadFormat))
	if format == "" {
		format = "json"
	}

	switch format {
	case "json", "raw":
		return &SyslogNGJSONEnvelopeParser{
			payloadFormat: format,
			jsonParser:    NewJSONParser(),
			messageField:  "MESSAGE",
		}, nil
	default:
		return nil, fmt.Errorf("unsupported syslog-ng payload format %q", payloadFormat)
	}
}

// Format returns the parser format identifier.
func (p *SyslogNGJSONEnvelopeParser) Format() string {
	return "syslog_ng_json"
}

// ParseLine parses a syslog-ng JSON envelope and optionally parses the nested MESSAGE payload.
func (p *SyslogNGJSONEnvelopeParser) ParseLine(line []byte) (Record, error) {
	outer, err := p.jsonParser.ParseLine(line)
	if err != nil {
		return nil, err
	}

	if !looksLikeSyslogNGEnvelope(outer) {
		return nil, ErrNotSyslogNGJSONEnvelope
	}

	result := make(Record, len(outer)+24)

	// Preserve original envelope keys as provided by syslog-ng.
	for key, value := range outer {
		result[key] = value
	}

	// Add normalized aliases for easier metric label configuration.
	copyAliasIfPresent(result, outer, "HOST", "syslog_host")
	copyAliasIfPresent(result, outer, "PROGRAM", "syslog_tag")
	copyAliasIfPresent(result, outer, "MESSAGE", "syslog_message")
	copyAliasIfPresent(result, outer, "PRIORITY", "syslog_priority")
	copyAliasIfPresent(result, outer, "FACILITY", "syslog_facility_text")
	copyAliasIfPresent(result, outer, "SOURCEIP", "syslog_sourceip")

	// Add explicit syslog-ng envelope aliases.
	copyAliasIfPresent(result, outer, "HOST", "syslogng_host")
	copyAliasIfPresent(result, outer, "PROGRAM", "syslogng_program")
	copyAliasIfPresent(result, outer, "MESSAGE", "syslogng_message")
	copyAliasIfPresent(result, outer, "PRIORITY", "syslogng_priority")
	copyAliasIfPresent(result, outer, "FACILITY", "syslogng_facility")
	copyAliasIfPresent(result, outer, "SOURCEIP", "syslogng_sourceip")
	copyAliasIfPresent(result, outer, "TAGS", "syslogng_tags")

	msg := outer[p.messageField]

	switch p.payloadFormat {
	case "raw":
		if strings.TrimSpace(msg) != "" {
			result["message"] = msg
		}
		setMeta(result, p.Format(), p.payloadFormat, "")
		return result, nil

	case "json":
		if strings.TrimSpace(msg) == "" {
			return nil, fmt.Errorf("syslog-ng envelope does not contain a non-empty %q field", p.messageField)
		}

		payload, err := p.jsonParser.ParseLine([]byte(msg))
		if err != nil {
			return nil, fmt.Errorf("parse syslog-ng MESSAGE payload as json: %w", err)
		}

		for key, value := range payload {
			result[key] = value
		}

		setMeta(result, p.Format(), p.payloadFormat, "")
		return result, nil

	default:
		return nil, fmt.Errorf("unsupported payload format %q", p.payloadFormat)
	}
}

// AutoParser detects the line format and delegates to the appropriate parser.
type AutoParser struct {
	jsonParser     *JSONParser
	rfc3164Parser  *RFC3164SyslogParser
	syslogNGParser *SyslogNGJSONEnvelopeParser
}

// NewAutoParser creates an auto-detect parser.
// The payloadFormat is used for syslog-based parsers that parse nested message payloads.
func NewAutoParser(payloadFormat string) (*AutoParser, error) {
	rfc3164Parser, err := NewRFC3164SyslogParser(payloadFormat)
	if err != nil {
		return nil, err
	}

	syslogNGParser, err := NewSyslogNGJSONEnvelopeParser(payloadFormat)
	if err != nil {
		return nil, err
	}

	return &AutoParser{
		jsonParser:     NewJSONParser(),
		rfc3164Parser:  rfc3164Parser,
		syslogNGParser: syslogNGParser,
	}, nil
}

// Format returns the parser format identifier.
func (p *AutoParser) Format() string {
	return "auto"
}

// ParseLine auto-detects syslog-ng JSON envelope, plain JSON, or RFC3164 syslog.
func (p *AutoParser) ParseLine(line []byte) (Record, error) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty line")
	}

	var errs []error

	// Fast path for JSON-looking payloads.
	if trimmed[0] == '{' {
		if record, err := p.syslogNGParser.ParseLine(trimmed); err == nil {
			record[MetaParserKey] = p.Format()
			return record, nil
		} else if !errors.Is(err, ErrNotSyslogNGJSONEnvelope) {
			errs = append(errs, fmt.Errorf("syslog-ng json parse failed: %w", err))
		}

		if record, err := p.jsonParser.ParseLine(trimmed); err == nil {
			setMeta(record, "json", "", p.Format())
			return record, nil
		} else {
			errs = append(errs, fmt.Errorf("json parse failed: %w", err))
		}
	}

	// RFC3164 syslog path.
	if record, err := p.rfc3164Parser.ParseLine(trimmed); err == nil {
		record[MetaParserKey] = p.Format()
		return record, nil
	} else {
		errs = append(errs, fmt.Errorf("rfc3164 parse failed: %w", err))
	}

	return nil, fmt.Errorf("auto parser could not detect supported format: %w", errors.Join(errs...))
}

// RFC3164SyslogParser parses RFC3164 syslog lines and optionally parses the MSG payload.
type RFC3164SyslogParser struct {
	payloadFormat string
	jsonParser    *JSONParser
}

// NewRFC3164SyslogParser creates an RFC3164 syslog parser.
// Supported payload formats are "json" and "raw".
func NewRFC3164SyslogParser(payloadFormat string) (*RFC3164SyslogParser, error) {
	format := strings.ToLower(strings.TrimSpace(payloadFormat))
	if format == "" {
		format = "json"
	}

	switch format {
	case "json", "raw":
		return &RFC3164SyslogParser{
			payloadFormat: format,
			jsonParser:    NewJSONParser(),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported syslog payload format %q", payloadFormat)
	}
}

// Format returns the parser format identifier.
func (p *RFC3164SyslogParser) Format() string {
	return "syslog_rfc3164"
}

// ParseLine parses an RFC3164 syslog envelope and then parses or stores the message payload.
func (p *RFC3164SyslogParser) ParseLine(line []byte) (Record, error) {
	env, err := parseRFC3164Envelope(line)
	if err != nil {
		return nil, err
	}

	record := make(Record, 16)
	record["syslog_pri"] = strconv.Itoa(env.PRI)
	record["syslog_facility"] = strconv.Itoa(env.Facility)
	record["syslog_severity"] = strconv.Itoa(env.Severity)
	record["syslog_timestamp"] = env.Timestamp
	record["syslog_host"] = env.Host
	record["syslog_tag"] = env.Tag
	record["syslog_pid"] = env.PID
	record["syslog_message"] = env.Message

	switch p.payloadFormat {
	case "raw":
		record["message"] = env.Message
		setMeta(record, p.Format(), p.payloadFormat, "")
		return record, nil

	case "json":
		payloadRecord, err := p.jsonParser.ParseLine([]byte(env.Message))
		if err != nil {
			return nil, fmt.Errorf("parse syslog message payload as json: %w", err)
		}

		for key, value := range payloadRecord {
			record[key] = value
		}
		setMeta(record, p.Format(), p.payloadFormat, "")
		return record, nil

	default:
		return nil, fmt.Errorf("unsupported payload format %q", p.payloadFormat)
	}
}

// RFC3164Envelope contains parsed header fields and the message payload.
type RFC3164Envelope struct {
	PRI       int
	Facility  int
	Severity  int
	Timestamp string
	Host      string
	Tag       string
	PID       string
	Message   string
}

var rfc3164Regex = regexp.MustCompile(
	`^(?:<(\d{1,3})>)?` +
		`([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+` +
		`(\S+)\s+` +
		`([^:\s]+(?:\[\d+\])?)` +
		`:\s?` +
		`(.*)$`,
)

var tagWithPIDRegex = regexp.MustCompile(`^([^\[]+)\[(\d+)\]$`)

// parseRFC3164Envelope parses a single RFC3164 syslog line.
func parseRFC3164Envelope(line []byte) (RFC3164Envelope, error) {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" {
		return RFC3164Envelope{}, fmt.Errorf("empty line")
	}

	matches := rfc3164Regex.FindStringSubmatch(trimmed)
	if matches == nil {
		return RFC3164Envelope{}, fmt.Errorf("line is not a supported RFC3164 syslog message")
	}

	pri := 13 // Default user.notice if PRI is omitted.
	if matches[1] != "" {
		parsedPRI, err := strconv.Atoi(matches[1])
		if err != nil {
			return RFC3164Envelope{}, fmt.Errorf("invalid PRI %q: %w", matches[1], err)
		}
		pri = parsedPRI
	}

	tag := matches[4]
	pid := ""
	if sub := tagWithPIDRegex.FindStringSubmatch(tag); sub != nil {
		tag = sub[1]
		pid = sub[2]
	}

	envelope := RFC3164Envelope{
		PRI:       pri,
		Facility:  pri / 8,
		Severity:  pri % 8,
		Timestamp: matches[2],
		Host:      matches[3],
		Tag:       tag,
		PID:       pid,
		Message:   matches[5],
	}

	return envelope, nil
}

// looksLikeSyslogNGEnvelope checks whether a parsed JSON object resembles a syslog-ng JSON envelope.
func looksLikeSyslogNGEnvelope(record Record) bool {
	if _, ok := record["MESSAGE"]; !ok {
		return false
	}
	return hasAnyKey(record, "PROGRAM", "HOST", "PRIORITY", "FACILITY", "SOURCEIP", "TAGS")
}

// hasAnyKey reports whether at least one key exists in the record.
func hasAnyKey(record Record, keys ...string) bool {
	for _, key := range keys {
		if _, ok := record[key]; ok {
			return true
		}
	}
	return false
}

// copyAliasIfPresent copies a value from src to dst under another key if the source key exists.
func copyAliasIfPresent(dst Record, src Record, srcKey string, dstKey string) {
	if value, ok := src[srcKey]; ok {
		dst[dstKey] = value
	}
}

// setMeta stores parser metadata fields on a parsed record.
func setMeta(record Record, inputFormat string, payloadFormat string, parserName string) {
	if inputFormat != "" {
		record[MetaInputFormatKey] = inputFormat
	}
	if payloadFormat != "" {
		record[MetaPayloadFormatKey] = payloadFormat
	}
	if parserName != "" {
		record[MetaParserKey] = parserName
	}
}

// toString converts common JSON value types to a stable string representation.
func toString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return strings.TrimSpace(string(data))
	}
}
