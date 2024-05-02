// go:generate go run go.uber.org/mock/mockgen -source builder.go -package builder -destination builder_mock.go ComponentBuilderFactory ComponentBuilder

package builder

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/digitalocean/doctl/commands/charm/template"
	"github.com/digitalocean/godo"
	"github.com/docker/docker/api/types"
	dockertypes "github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/stdcopy"
)

// ComponentBuilderFactory is the interface for creating component detector.
type DetectorFactory interface {
	NewComponentDetector(DockerEngineClient, NewDetectorOpts) (ComponentDetector, error)
}

// ComponentDetector is the interface of building one or more components.
type ComponentDetector interface {
	Detect(context.Context) (DetectResponse, error)
}

type DetectResponse struct {
	Components    []*DetectResponseComponent `json:"components,omitempty"`
	Template      *godo.AppSpec              `json:"template,omitempty"`
	TemplateFound bool                       `json:"template_found,omitempty"`
	TemplateValid bool                       `json:"template_valid,omitempty"`
	TemplateError string                     `json:"template_error,omitempty"`
	ExitCode      int
}

type DetectResponseComponent struct {
	Strategy DetectResponseType `json:"strategy,omitempty"`
	Types    []string           `json:"types,omitempty"`
	// A list of Dockerfiles that were found for this component. The recommendation is to use the first Dockerfile.
	Dockerfiles     []string `json:"dockerfiles,omitempty"`
	BuildCommand    string   `json:"build_command,omitempty"`
	RunCommand      string   `json:"run_command,omitempty"`
	EnvironmentSlug string   `json:"environment_slug,omitempty"`
	// A list of HTTP ports that this component may listen on. The recommendation is to use the last port in the list.
	HTTPPorts []int64                  `json:"http_ports,omitempty"`
	EnvVars   []*AppVariableDefinition `json:"env_vars,omitempty"`
	// List of serverless packages detected.
	ServerlessPackages []*DetectResponseServerlessPackage `json:"serverless_packages,omitempty"`
	SourceDir          string                             `json:"source_dir,omitempty"`
	// The list of detected buildpacks that will be used for the component build.
	Buildpacks []*Buildpack `json:"buildpacks,omitempty"`
}

// DetectResponseServerlessPackage struct for DetectResponseServerlessPackage
type DetectResponseServerlessPackage struct {
	// Name of the serverless package.
	Name string `json:"name,omitempty"`
	// List of functions detected in the serverless package.
	Functions []*DetectResponseServerlessFunction `json:"functions,omitempty"`
}

// DetectResponseServerlessFunction struct for DetectResponseServerlessFunction
type DetectResponseServerlessFunction struct {
	// Name of the function.
	Name string `json:"name,omitempty"`
	// Package that the function belongs to.
	Package string `json:"package,omitempty"`
	// Runtime detected for the function.
	Runtime string                                  `json:"runtime,omitempty"`
	Limits  *DetectResponseServerlessFunctionLimits `json:"limits,omitempty"`
}

// DetectResponseServerlessFunctionLimits struct for DetectResponseServerlessFunctionLimits
type DetectResponseServerlessFunctionLimits struct {
	// Timeout for function invocation in milliseconds.
	Timeout string `json:"timeout,omitempty"`
	// Max memory allocation for function invocation in megabytes.
	Memory string `json:"memory,omitempty"`
	// Max log size usage for function invocation in kilobytes.
	Logs string `json:"logs,omitempty"`
}

// DetectResponseType the model 'DetectResponseType'
type DetectResponseType string

type AppVariableDefinition struct {
	// The name
	Key string `json:"key"`
	// The value. If the type is `SECRET`, the value will be encrypted on first submission. On following submissions, the encrypted value should be used.
	Value string           `json:"value,omitempty"`
	Scope AppVariableScope `json:"scope,omitempty"`
	Type  AppVariableType  `json:"type,omitempty"`
}

type AppVariableScope string

// AppVariableType the model 'AppVariableType'
type AppVariableType string

type DefaultComponentDetectorFactory struct{}

// NewDetectorOpts ...
type NewDetectorOpts struct {
	CNBBuilderImage string
	ContextDir      string
	LogWriter       io.Writer
}



type BaseComponentDetector struct {
	cli        DockerEngineClient
	contextDir string
	copyOnWriteSemantics bool
	detectContainer      containertypes.CreateResponse
	logWriter io.Writer
	CNBBuilderImage string
}

func (df *DefaultComponentDetectorFactory) NewComponentDetector(cli DockerEngineClient, opts NewDetectorOpts) (ComponentDetector, error) {
	return &BaseComponentDetector{
		cli:                  cli,
		contextDir:           opts.ContextDir,
		logWriter:            opts.LogWriter,
		CNBBuilderImage:      opts.CNBBuilderImage,
		copyOnWriteSemantics: true,
	}, nil
}

func (b *BaseComponentDetector) Detect(ctx context.Context) (res DetectResponse, err error) {
	_, err = ImageExists(ctx, b.cli, b.CNBBuilderImage)

	if err != nil {
		return res, fmt.Errorf("CNB Builder image not found %w", err)
	}

	var sourceDockerSock string
	switch runtime.GOOS {
	case "darwin", "windows":
		// mac/windows docker-for-desktop includes the raw socket in the VM
		sourceDockerSock = "/var/run/docker.sock.raw"
	default:
		sourceDockerSock, err = filepath.EvalSymlinks(dockerSocketPath)
		if err != nil {
			return res, fmt.Errorf("finding docker engine socket: %w", err)
		}
	}

	mounts := []mount.Mount{{
		Type:   mount.TypeBind,
		Source: sourceDockerSock,
		Target: dockerSocketPath,
	}}
	if !b.copyOnWriteSemantics {
		mounts = append(mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: b.contextDir,
			Target: "/workspace/",
		})
	}

	// if b.localCacheDir != "" {
	// 	mounts = append(mounts, mount.Mount{
	// 		Type:   mount.TypeBind,
	// 		Source: b.localCacheDir,
	// 		Target: cnbCacheDir,
	// 	})
	// }

	b.detectContainer, err = b.cli.ContainerCreate(ctx, &containertypes.Config{
		Image:        b.CNBBuilderImage,
		Entrypoint:   []string{"sh", "-c", "sleep infinity"},
		AttachStdout: true,
		AttachStderr: true,
	}, &containertypes.HostConfig{
		Mounts: mounts,
	}, nil, nil, "")
	if err != nil {
		return res, fmt.Errorf("creating build container: %w", err)
	}

	// start := time.Now()
	defer func() {
		// res.BuildDuration = time.Since(start)
		// we use context.Background() so we can remove the container if the original context is cancelled.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = b.cli.ContainerRemove(ctx, b.detectContainer.ID, dockertypes.ContainerRemoveOptions{
			Force: true,
		})
		b.detectContainer = containertypes.CreateResponse{}
	}()

	if err := b.cli.ContainerStart(ctx, b.detectContainer.ID, dockertypes.ContainerStartOptions{}); err != nil {
		return res, fmt.Errorf("starting detect container: %w", err)
	}

	lw := b.getLogWriter()
	if !b.copyOnWriteSemantics {
		template.Render(lw, "{{success checkmark}} mounting app workspace{{nl}}", nil)
	} else {
		template.Render(lw, heredoc.Doc(`
			{{success checkmark}} copying local app workspace to build container
			  {{muted (print "    local: " .)}}
			  {{muted "container: /workspace"}}
		`), b.contextDir)
		// Prepare source copy info.
		srcInfo, err := archive.CopyInfoSourcePath(b.contextDir, true)
		if err != nil {
			return res, fmt.Errorf("preparing app workspace: %w", err)
		}
		srcArchive, err := archive.TarResource(srcInfo)
		if err != nil {
			return res, fmt.Errorf("preparing app workspace: %w", err)
		}
		defer srcArchive.Close()
		dstInfo := archive.CopyInfo{
			Path:  "/workspace",
			IsDir: true,
		}
		archDir, preparedArchive, err := archive.PrepareArchiveCopy(srcArchive, srcInfo, dstInfo)
		if err != nil {
			return res, fmt.Errorf("archiving app workspace: %w", err)
		}
		defer preparedArchive.Close()
		err = b.cli.CopyToContainer(ctx, b.detectContainer.ID, archDir, preparedArchive, dockertypes.CopyToContainerOptions{
			AllowOverwriteDirWithFile: false,
			CopyUIDGID:                false,
		})
		if err != nil {
			return res, fmt.Errorf("copying app workspace to build container: %w", err)
		}
	}

	env := []string{"debug"}

	template.Render(lw, "{{success checkmark}} Detecting{{nl 2}}", nil)

	//TODO: add extra flags as per the config.
	runCmd := []string{"sh", "-c", "/.app_platform/appdetect -empty -debug -all -clean-up=false -app=/workspace/ /workspace"}


	err = b.runExec(
		ctx,
		b.detectContainer.ID,
		runCmd,
		env,
		b.getLogWriter(),
		nil,
	)

	if err != nil {
		return res, err
	}
	return res, nil
}

func (b BaseComponentDetector) getLogWriter() io.Writer {
	if b.logWriter == nil {
		return os.Stdout
	}
	return b.logWriter
}

func (b *BaseComponentDetector) runExec(ctx context.Context, containerID string, command, env []string, output io.Writer, input io.Reader) error {
	if output == nil {
		output = io.Discard
	}
	execRes, err := b.cli.ContainerExecCreate(ctx, containerID, types.ExecConfig{
		AttachStderr: true,
		AttachStdout: true,
		AttachStdin:  input != nil,
		Env:          env,
		Cmd:          command,
	})
	if err != nil {
		return fmt.Errorf("creating container exec: %w", err)
	}

	// read the output
	attachRes, err := b.cli.ContainerExecAttach(ctx, execRes.ID, types.ExecStartCheck{})
	if err != nil {
		return fmt.Errorf("attaching to container exec: %w", err)
	}
	defer attachRes.Close()
	outputDone := make(chan error)

	var wg sync.WaitGroup
	if input != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			io.Copy(attachRes.Conn, input)
			attachRes.CloseWrite()
		}()
	}
	go func() {
		// StdCopy demultiplexes the stream into two separate stdout and stderr buffers
		_, err := stdcopy.StdCopy(output, output, attachRes.Reader)
		outputDone <- err
	}()

	select {
	case err = <-outputDone:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		return err
	}

	wg.Wait()

	// the exec process completed. check its exit code and return an error if it failed.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := b.cli.ContainerExecInspect(ctx, execRes.ID)
	if err != nil {
		return fmt.Errorf("inspecting container: %w", err)
	} else if res.ExitCode > 0 {
		return ContainerExecError{
			Err:      fmt.Errorf("command exited with a non-zero status code"),
			ExitCode: res.ExitCode,
		}
	}

	return nil
}
