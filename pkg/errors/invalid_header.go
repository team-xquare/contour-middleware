package errors

import "strings"

type InvalidHeaderError struct {
	NotAvailableHeaders []string
}

func NewInvalidHeaderError(headers []string) InvalidHeaderError {
	return InvalidHeaderError{headers}
}

func (e InvalidHeaderError) Error() string {
	message := strings.Join(e.NotAvailableHeaders, ", ")
	return "Not available header name: " + message
}
