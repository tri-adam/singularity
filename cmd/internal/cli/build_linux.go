// Copyright (c) 2019, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package cli

import (
	"context"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"github.com/sylabs/singularity/internal/pkg/build"
	"github.com/sylabs/singularity/internal/pkg/build/remotebuilder"
	"github.com/sylabs/singularity/internal/pkg/sylog"
	"github.com/sylabs/singularity/pkg/build/types"
)

func run(cmd *cobra.Command, args []string) {
	buildFormat := "sif"
	if sandbox {
		buildFormat = "sandbox"
	}

	dest := args[0]
	spec := args[1]

	// check if target collides with existing file
	if ok := checkBuildTarget(dest, update); !ok {
		os.Exit(1)
	}

	if remote {
		// Submiting a remote build requires a valid authToken
		if authToken == "" {
			sylog.Fatalf("Unable to submit build job: %v", authWarning)
		}

		def, err := definitionFromSpec(spec)
		if err != nil {
			sylog.Fatalf("Unable to build from %s: %v", spec, err)
		}

		if sandbox {
			// create temporary file to download sif
			f, err := ioutil.TempFile(tmpDir, "remote-build-")
			if err != nil {
				sylog.Fatalf("Could not create temporary directory: %s", err)
			}
			os.Remove(f.Name())
			dest = f.Name()

			// remove downloaded sif
			defer os.Remove(f.Name())

			// build from sif downloaded in tmp location
			defer func() {
				sylog.Debugf("Building sandbox from downloaded SIF")

				//
				// This build was performed with a different build api in the original commit
				// I have changed it to use the api relevant in this 3.1.x branch, the functionality
				// should not have changed. Original code is in comment bellow:
				//
				//
				// d, err := types.NewDefinitionFromURI("localimage" + "://" + dest)
				// if err != nil {
				// 	sylog.Fatalf("Unable to create definition for sandbox build: %v", err)
				// }
				//
				// b, err := build.New(
				// 	[]types.Definition{d},
				// 	build.Config{
				// 		Dest:      args[0],
				// 		Format:    buildFormat,
				// 		NoCleanUp: noCleanUp,
				// 		Opts: types.Options{
				// 			TmpDir: tmpDir,
				// 			Update: update,
				// 			Force:  force,
				// 		},
				// 	})

				b, err := build.NewBuild(
					dest,
					args[0],
					buildFormat,
					"",
					"",
					types.Options{
						NoCleanUp: noCleanUp,
						TmpDir:    tmpDir,
						Update:    update,
						Force:     force,
					},
				)
				if err != nil {
					sylog.Fatalf("Unable to create build: %v", err)
				}

				if err = b.Full(); err != nil {
					sylog.Fatalf("While performing build: %v", err)
				}
			}()
		}

		b, err := remotebuilder.New(dest, libraryURL, def, detached, force, builderURL, authToken)
		if err != nil {
			sylog.Fatalf("Failed to create builder: %v", err)
		}
		err = b.Build(context.TODO())
		if err != nil {
			sylog.Fatalf("While performing build: %v", err)
		}
	} else {

		err := checkSections()
		if err != nil {
			sylog.Fatalf(err.Error())
		}

		authConf, err := makeDockerCredentials(cmd)
		if err != nil {
			sylog.Fatalf("While creating Docker credentials: %v", err)
		}

		b, err := build.NewBuild(
			spec,
			dest,
			buildFormat,
			libraryURL,
			authToken,
			types.Options{
				TmpDir:           tmpDir,
				Update:           update,
				Force:            force,
				Sections:         sections,
				NoTest:           noTest,
				NoHTTPS:          noHTTPS,
				NoCleanUp:        noCleanUp,
				DockerAuthConfig: authConf,
			})
		if err != nil {
			sylog.Fatalf("Unable to create build: %v", err)
		}

		if err = b.Full(); err != nil {
			sylog.Fatalf("While performing build: %v", err)
		}
	}
}
