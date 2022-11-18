package metric

import (
	"encoding/json"
	"hash/maphash"
	"log"
	"strings"
	"time"

	"github.com/influxdata/telegraf"
)

const (
	GBPVALUE  = "ValueByType"
	GBPFIELDS = "fields"
	GBPNAME   = "name"
	Nexus     = "NX-OS"
)

type Row struct {
	Timestamp float64
	Content   interface{}
	Keys      interface{}
}

type Field struct {
	Rows      []Row
	Telemetry map[string]interface{}
	Source    string

	Log telegraf.Logger
}

func NewField() *Field {
	return &Field{}
}

type Grouper struct {
	metrics map[uint64]telegraf.Metric
	ordered []telegraf.Metric

	hashSeed maphash.Seed
}

func NewGrouper() *Grouper {
	return &Grouper{
		metrics:  make(map[uint64]telegraf.Metric),
		ordered:  []telegraf.Metric{},
		hashSeed: maphash.MakeSeed(),
	}
}

func (g *Grouper) Add(
	measurement string,
	tm time.Time,
	field string,
	fieldValue interface{},
) error {
	id := groupID(g.hashSeed, measurement, nil, tm)
	m := g.metrics[id]
	if m == nil {
		m = New(measurement, nil, map[string]interface{}{field: fieldValue}, tm)
		g.metrics[id] = m
		g.ordered = append(g.ordered, m)
		m.AddField(field, fieldValue)
	} else {
		m.AddField(field, fieldValue)
	}
	return nil
}

func (g *Grouper) AddMetric(
	metric telegraf.Metric,
) {
	id := groupID(g.hashSeed, metric.Name(), metric.TagList(), metric.Time())
	m := g.metrics[id]
	if m == nil {
		m = metric.Copy()
		g.metrics[id] = m
		g.ordered = append(g.ordered, m)
	} else {
		for _, f := range metric.FieldList() {
			m.AddField(f.Key, f.Value)
		}
	}
}

func (g *Grouper) Metrics() []telegraf.Metric {
	return g.ordered
}

func (f *Field) GbpkvParse(data []byte, sourceIP string) {
	f.Source = sourceIP
	var v interface{}
	err := json.Unmarshal(data, &v)
	if err != nil {
		log.Println("unmarshal json err: ", err)
	}

	gpbkv := v.(map[string]interface{})
	f.Telemetry = make(map[string]interface{}, 0)

	for k, v := range gpbkv {
		if k != "data_gpbkv" {
			f.parseTelemetry(f.Telemetry, k, v)
		} else {
			f.Rows = f.parseRow(v)
		}
	}
}

func (f *Field) parseTelemetry(telemetry map[string]interface{}, key string, value interface{}) {
	if e, ok := value.(map[string]interface{}); ok {
		for k, v := range e {
			k = CamelCaseToUnderscore(k)
			telemetry[k] = decodeValue(v)
		}
	} else {
		key = CamelCaseToUnderscore(key)
		telemetry[key] = decodeValue(value)
	}
}

func (f *Field) parseRow(value interface{}) []Row {
	var rowArr []Row
	for _, arr := range value.([]interface{}) {
		var row Row
		data := arr.(map[string]interface{})
		if data[GBPVALUE] == nil && data[GBPFIELDS] != nil {
			if data["timestamp"] != nil {
				row.Timestamp = data["timestamp"].(float64)
			}
			field := f.parseFields(data[GBPFIELDS])
			if _, ok := field["content"]; ok {
				row.Content = field["content"]
			} else {
				f.Log.Errorf("no field named rows")
			}
			if _, ok := field["keys"]; ok {
				row.Keys = field["keys"]
			} else {
				f.Log.Errorf("no field named keys")
			}
			//row.Rows = field
			rowArr = append(rowArr, row)
		}
	}
	return rowArr
}

func (f *Field) parseFields(v interface{}) map[string]interface{} {
	s := make(map[string]interface{})
	placeInArrayMap := map[string]bool{}
	for _, arr := range v.([]interface{}) {
		field := arr.(map[string]interface{})
		var fieldVal interface{}
		var hint int
		var key string
		if field[GBPNAME] == nil && field[GBPFIELDS] != nil {
			// nx-os every field have a map like this {"": {}}
			key = Nexus
		} else {
			key = field[GBPNAME].(string)
		}
		existingEntry, exists := s[key]
		_, placeInArray := placeInArrayMap[key]
		_, children := field[GBPFIELDS]
		if !children {
			fieldVal = field[GBPVALUE]
			if fieldVal != nil {
				for _, value := range fieldVal.(map[string]interface{}) {
					fieldVal = value
				}
			}
			hint = 10
		} else {
			fieldVal = f.parseFields(field[GBPFIELDS])
			for nilK, nilV := range fieldVal.(map[string]interface{}) {
				if nilK == Nexus {
					fieldVal = nilV
				}
			}
			hint = len(field[GBPFIELDS].([]interface{}))
		}

		if !placeInArray && !exists {
			// this is the common case by far!
			s[key] = fieldVal
		} else {
			newName := key + "_arr"
			if exists {
				if !placeInArray {
					// Create list
					s[newName] = make([]interface{}, 0, hint)
					// Remember that this field name is arrayified(!?)
					placeInArrayMap[key] = true
					// Add existing entry to new array)
					s[newName] = append(s[newName].([]interface{}), existingEntry)
					// Delete existing entry from old
					delete(s, key)
					placeInArray = true
				} else {
					f.Log.Errorf("gbpkv inconsistency, processing repeated field names")
				}
			}
			if placeInArray && fieldVal != nil {
				s[newName] = append(s[newName].([]interface{}), fieldVal)
			}
		}
	}
	return s
}

func decodeValue(v interface{}) interface{} {
	switch v := v.(type) {
	case float64:
		return v
	case int64:
		return v
	case string:
		return v
	case bool:
		return v
	case int:
		return int64(v)
	case uint:
		return uint64(v)
	case uint64:
		return v
	case []byte:
		return string(v)
	case int32:
		return int64(v)
	case int16:
		return int64(v)
	case int8:
		return int64(v)
	case uint32:
		return uint64(v)
	case uint16:
		return uint64(v)
	case uint8:
		return uint64(v)
	case float32:
		return float64(v)
	case *float64:
		if v != nil {
			return *v
		}
	case *int64:
		if v != nil {
			return *v
		}
	case *string:
		if v != nil {
			return *v
		}
	case *bool:
		if v != nil {
			return *v
		}
	case *int:
		if v != nil {
			return int64(*v)
		}
	case *uint:
		if v != nil {
			return uint64(*v)
		}
	case *uint64:
		if v != nil {
			return *v
		}
	case *[]byte:
		if v != nil {
			return string(*v)
		}
	case *int32:
		if v != nil {
			return int64(*v)
		}
	case *int16:
		if v != nil {
			return int64(*v)
		}
	case *int8:
		if v != nil {
			return int64(*v)
		}
	case *uint32:
		if v != nil {
			return uint64(*v)
		}
	case *uint16:
		if v != nil {
			return uint64(*v)
		}
	case *uint8:
		if v != nil {
			return uint64(*v)
		}
	case *float32:
		if v != nil {
			return float64(*v)
		}
	default:
		return nil
	}
	return nil
}

func CamelCaseToUnderscore(s string) string {
	data := make([]byte, 0, len(s)*2)
	j := false
	num := len(s)
	for i := 0; i < num; i++ {
		d := s[i]
		if i > 0 && d >= 'A' && d <= 'Z' && j {
			data = append(data, '_')
		}
		if d != '_' {
			j = true
		}
		data = append(data, d)
	}
	return strings.ToLower(string(data[:]))
}
