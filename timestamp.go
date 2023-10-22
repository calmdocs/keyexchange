package keyexchange

import (
	"strconv"
	"time"
)

// AuthTimestamp converts additionalData ([]byte) into an int64 timestamp,
// ensurest that this timestamp is after the latestTimestamp,
// and ensures the timestamp is within the last 10 milliseconds
func AuthTimestamp(additionalData []byte, latestTimestamp int64) (bool, int64, error) {

	// Only process new messages
	i, err := strconv.ParseInt(string(additionalData), 10, 64)
	if err != nil {
		return false, 0, err
	}
	if i <= latestTimestamp {
		return false, 0, nil
	}
	// Allow up to 10 milliseconds of jitter
	delta := time.Now().UTC().UnixMilli() - i
	if delta < 0 || delta > 10 {
		return false, 0, nil
	}
	return true, i, nil
}

// CurrentTimestamp is the current time since 1970 in milliseconds as an int64.
func CurrentTimestamp() int64 {
	return time.Now().UTC().UnixMilli()
}

// CurrentTimestampString is the current time since 1970 in milliseconds as a string.
func CurrentTimestampString() string {
	return strconv.FormatInt(CurrentTimestamp(), 10)
}

// CurrentTimestampBytes is the current time since 1970 in milliseconds as a bytes.
func CurrentTimestampBytes() []byte {
	return []byte(CurrentTimestampString())
}
