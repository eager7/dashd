// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"github.com/eager7/dashlog"
)

// log is a logger that is initialized with no output filters.  This
// means the package will not perform any logging by default until the caller
// requests it.
var log dashlog.Logger

// The default amount of logging is none.
func init() {
	DisableLog()
}

// DisableLog disables all library log output.  Logging output is disabled
// by default until either UseLogger or SetLogWriter are called.
func DisableLog() {
	log = dashlog.Disabled
}

// UseLogger uses a specified Logger to output package logging info.
// This should be used in preference to SetLogWriter if the caller is also
// using dashlog.
func UseLogger(logger dashlog.Logger) {
	log = logger
}
