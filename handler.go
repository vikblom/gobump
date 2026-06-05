package main

// Message is an entry in the output stream. It will always have exactly one
// field filled in.
type Message struct {
	SBOM    *SBOM    `json:"SBOM,omitempty"`
	Finding *Finding `json:"finding,omitempty"`

	// Irrelevant fields omitted.
}

type SBOM struct {
	// The go version used by govulncheck when scanning, which also defines
	// the version of the standard library used for detecting vulns.
	GoVersion string `json:"go_version,omitempty"`

	// The set of modules included in the scan.
	Modules []*Module `json:"modules,omitempty"`

	// The roots of the scan, as package paths.
	// For binaries, this will be the main package.
	// For source code, this will be the packages matching the provided package patterns.
	Roots []string `json:"roots,omitempty"`
}

type Module struct {
	// The full module path.
	Path string `json:"path,omitempty"`

	// The version of the module.
	Version string `json:"version,omitempty"`
}

// Finding contains information on a discovered vulnerability. Each vulnerability
// will likely have multiple findings in JSON mode. This is because govulncheck
// emits findings as it does work, and therefore could emit one module level,
// one package level, and potentially multiple symbol level findings depending
// on scan level.
// Multiple symbol level findings can be emitted when multiple symbols of the
// same vuln are called or govulncheck decides to show multiple traces for the
// same symbol.
type Finding struct {
	// OSV is the id of the detected vulnerability.
	OSV string `json:"osv,omitempty"`

	// FixedVersion is the module version where the vulnerability was
	// fixed. This is empty if a fix is not available.
	//
	// If there are multiple fixed versions in the OSV report, this will
	// be the fixed version in the latest range event for the OSV report.
	//
	// For example, if the range events are
	// {introduced: 0, fixed: 1.0.0} and {introduced: 1.1.0}, the fixed version
	// will be empty.
	//
	// For the stdlib, we will show the fixed version closest to the
	// Go version that is used. For example, if a fix is available in 1.17.5 and
	// 1.18.5, and the GOVERSION is 1.17.3, 1.17.5 will be returned as the
	// fixed version.
	FixedVersion string `json:"fixed_version,omitempty"`

	// Trace contains an entry for each frame in the trace.
	//
	// Frames are sorted starting from the imported vulnerable symbol
	// until the entry point. The first frame in Frames should match
	// Symbol.
	//
	// In binary mode, trace will contain a single-frame with no position
	// information.
	//
	// For module level source findings, the trace will contain a single-frame
	// with no symbol, position, or package information. For package level source
	// findings, the trace will contain a single-frame with no symbol or position
	// information.
	Trace []*Frame `json:"trace,omitempty"`
}

// Frame represents an entry in a finding trace.
type Frame struct {
	// Module is the module path of the module containing this symbol.
	//
	// Importable packages in the standard library will have the path "stdlib".
	Module string `json:"module"`

	// Version is the module version from the build graph.
	Version string `json:"version,omitempty"`

	// Package is the import path.
	Package string `json:"package,omitempty"`

	// Function is the function name.
	Function string `json:"function,omitempty"`

	// Receiver is the receiver type if the called symbol is a method.
	//
	// The client can create the final symbol name by
	// prepending Receiver to FuncName.
	Receiver string `json:"receiver,omitempty"`

	// Position describes an arbitrary source position
	// including the file, line, and column location.
	// A Position is valid if the line number is > 0.
	//
	// The filenames are relative to the directory of
	// the enclosing module and always use "/" for
	// portability.
	Position *Position `json:"position,omitempty"`
}

// Position represents arbitrary source position.
type Position struct {
	Filename string `json:"filename,omitempty"` // filename, if any
	Offset   int    `json:"offset"`             // byte offset, starting at 0
	Line     int    `json:"line"`               // line number, starting at 1
	Column   int    `json:"column"`             // column number, starting at 1 (byte count)
}
