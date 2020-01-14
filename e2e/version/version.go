// Copyright (c) 2019, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package version

import (
	"strings"
	"testing"

	"github.com/sylabs/singularity/e2e/internal/e2e"
	"github.com/sylabs/singularity/e2e/internal/testhelper"
)

type ctx struct {
	env e2e.TestEnv
}

var tests = []struct {
	name string
	args []string
}{
	{"version command", []string{"version"}},
	{"version flag", []string{"--version"}},
}

//Test that both versions when running: singularity --version and
// singularity version give the same result
func (c ctx) testEqualVersion(t *testing.T) {
	var tmpVersion = ""
	for _, tt := range tests {

		checkEqualVersionFn := func(t *testing.T, r *e2e.SingularityCmdResult) {
			outputVer := strings.TrimPrefix(string(r.Stdout), "singularity version ")
			outputVer = strings.TrimPrefix(outputVer, "SingularityPRO version ")
			outputVer = strings.TrimSpace(outputVer)
			if tmpVersion != "" {
				if outputVer != tmpVersion {
					t.Fatalf("singularity version command and singularity --version give a non-matching version result: %s != %s", outputVer, tmpVersion)
				}
			} else {
				tmpVersion = outputVer
			}
		}

		c.env.RunSingularity(
			t,
			e2e.WithProfile(e2e.UserProfile),
			e2e.WithArgs(tt.args...),
			e2e.PostRun(func(t *testing.T) {
				if t.Failed() {
					t.Log("Failed to obtain version")
				}
			}),
			e2e.ExpectExit(0, checkEqualVersionFn),
		)

	}
}

// Test the help option
func (c ctx) testHelpOption(t *testing.T) {
	c.env.RunSingularity(
		t,
		e2e.WithProfile(e2e.UserProfile),
		e2e.WithCommand("version"),
		e2e.WithArgs("--help"),
		e2e.ExpectExit(
			0,
			e2e.ExpectOutput(e2e.RegexMatch, "^Show the version for Singularity"),
		),
	)
}

// E2ETests is the main func to trigger the test suite
func E2ETests(env e2e.TestEnv) func(*testing.T) {
	c := ctx{
		env: env,
	}

	return testhelper.TestRunner(map[string]func(*testing.T){
		"equal version": c.testEqualVersion,
		"help option":   c.testHelpOption,
	})
}
