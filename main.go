package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/hashicorp/go-version"
	"golang.org/x/mod/modfile"
	"golang.org/x/vuln/scan"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGKILL)
	defer cancel()
	err := run(ctx)
	switch err := err.(type) {
	case nil:
	case interface{ ExitCode() int }:
		os.Exit(err.ExitCode())
	default:
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func defaultArgs() []string {
	if len(os.Args) > 1 {
		return os.Args[1:]
	}
	return []string{"./..."}
}

func run(ctx context.Context) error {
	scannedModule, err := readModuleName()
	if err != nil {
		return err
	}

	args := append([]string{
		"-format=json",
	},
		defaultArgs()...,
	)
	cmd := scan.Command(ctx, args...)

	var buf bytes.Buffer
	cmd.Stdout = &buf

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("starting scan: %w", err)
	}
	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	var findings []Finding
	dec := json.NewDecoder(&buf)
	for dec.More() {
		msg := Message{}
		err := dec.Decode(&msg)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("decoder: %w", err)
		}
		switch {
		case msg.Finding != nil:
			findings = append(findings, *msg.Finding)
		}
	}
	if len(findings) == 0 {
		return nil // Nothing to do.
	}

	fixes := map[string]*version.Version{}
	for _, f := range findings {
		// fmt.Printf("%s %s %s from %s\n", f.OSV, f.Trace[0].Module, f.FixedVersion, f.Trace[len(f.Trace)-1].Module)
		// Check if the vulnerability is reachable from our roots.
		// If not then it is irrelevant.
		if f.Trace[len(f.Trace)-1].Module == scannedModule {
			fixed, err := version.NewVersion(f.FixedVersion)
			if err != nil {
				return fmt.Errorf("invalid version: %w", err)
			}
			// Make sure we store the version needed to fix all findings.
			if prev, ok := fixes[f.Trace[0].Module]; ok {
				if prev.GreaterThan(fixed) {
					continue
				}
			}
			fixes[f.Trace[0].Module] = fixed
		}
	}

	getargs := []string{"get"}

	// Fixup the name of stdlib.
	if ver, found := fixes["stdlib"]; found {
		delete(fixes, "stdlib")
		getargs = append(getargs, "go@go"+ver.String())
	}
	for mod, ver := range fixes {
		getargs = append(getargs, mod+"@v"+ver.String())
	}

	// Go get all the relevant fixes.
	goCmd := exec.CommandContext(ctx, "go", getargs...)
	fmt.Println(goCmd.String())
	err = goCmd.Start()
	if err != nil {
		return fmt.Errorf("go get start: %w", err)
	}
	return goCmd.Wait()
}

func readModuleName() (string, error) {
	bs, err := os.ReadFile("go.mod")
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	return modfile.ModulePath(bs), nil
}
