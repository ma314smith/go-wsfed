package wsfed

import "time"

const iso8601Layout = "2006-01-02T15:04:05Z"

func parseISO8601Time(s string) (time.Time, error) {
	t, err := time.Parse(iso8601Layout, s)
	return t, err
}

func convertTimeToISO8601(t time.Time) string {
	return t.Format(iso8601Layout)
}
