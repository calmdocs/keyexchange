package keyexchange

import (
	"fmt"
	"strconv"
	"time"
)

// AuthTimestamp converts additionalData ([]byte) into an int64 timestamp,
// ensures that this timestamp is after the latestTimestamp,
// and ensures the timestamp is within the last 10 milliseconds
func AuthTimestamp(additionalData []byte, latestTimestamp int64) (ok bool, ts int64, err error) {

	// Parse int64
	ts, err = strconv.ParseInt(string(additionalData), 10, 64)
	if err != nil {
		return false, 0, err
	}

	// Only process new messages
	err = authTimestampIsValidCheck(ts, latestTimestamp)
	if err != nil {
		fmt.Println(err.Error())
		return false, 0, err
	}
	return true, ts, nil
}

func authTimestampIsValidCheck(ts, latestTimestamp int64) (err error) {

	// Check against latest timestamp
	if ts <= latestTimestamp {
		return fmt.Errorf("timestamp expired")
	}

	/*
		// Allow up to 5 seconds of jitter
		delta := time.Now().UTC().UnixMilli() - ts
		switch {
		case delta < 5000:
			return fmt.Errorf("timestamp in the past error")
		case delta > 5000:
			return fmt.Errorf("timestamp in the future error")
		default:
		}
	*/
	return nil
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
