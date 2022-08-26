package errors

import "strings"

type NotAvailableHeaderError struct {
	NotAvailableHeaders []string
}

func NewNotAvailableHeaderError(headers []string) NotAvailableHeaderError {
	return NotAvailableHeaderError{headers}
}

func (e NotAvailableHeaderError) Error() string {
	message := strings.Join(e.NotAvailableHeaders, ", ")
	return "Not available header name: " + message
}
