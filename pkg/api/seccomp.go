/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package api

import (
	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

func FromOCILinuxSeccomp(o rspec.LinuxSeccomp) *LinuxSeccomp {
	var errno *OptionalInt
	if o.DefaultErrnoRet != nil {
		errno = &OptionalInt{Value: int64(*o.DefaultErrnoRet)}
	}

	arches := []string{}
	for _, arch := range o.Architectures {
		arches = append(arches, string(arch))
	}

	flags := []string{}
	for _, flag := range o.Flags {
		flags = append(flags, string(flag))
	}

	return &LinuxSeccomp{
		DefaultAction:    string(o.DefaultAction),
		DefaultErrno:     errno,
		Architectures:    arches,
		Flags:            flags,
		ListenerPath:     o.ListenerPath,
		ListenerMetadata: o.ListenerMetadata,
		Syscalls:         FromOCILinuxSyscalls(o.Syscalls),
	}
}

func FromOCILinuxSyscalls(o []rspec.LinuxSyscall) []*LinuxSyscall {
	syscalls := []*LinuxSyscall{}

	for _, syscall := range o {
		var errno *OptionalInt
		if syscall.ErrnoRet != nil {
			errno = &OptionalInt{Value: int64(*syscall.ErrnoRet)}
		}

		syscalls = append(syscalls, &LinuxSyscall{
			Names:    syscall.Names,
			Action:   string(syscall.Action),
			ErrnoRet: errno,
			Args:     FromOCILinuxSeccompArgs(syscall.Args),
		})
	}

	return syscalls
}

func FromOCILinuxSeccompArgs(o []rspec.LinuxSeccompArg) []*LinuxSeccompArg {
	args := []*LinuxSeccompArg{}

	for _, arg := range o {
		args = append(args, &LinuxSeccompArg{
			Index:    uint32(arg.Index),
			Value:    arg.Value,
			ValueTwo: arg.ValueTwo,
			Op:       string(arg.Op),
		})
	}

	return args
}

func ToOCILinuxSyscalls(o []*LinuxSyscall) []rspec.LinuxSyscall {
	syscalls := []rspec.LinuxSyscall{}

	for _, syscall := range o {
		var errnoRet *uint

		if syscall.ErrnoRet != nil {
			*errnoRet = uint(syscall.ErrnoRet.Value)
		}

		syscalls = append(syscalls, rspec.LinuxSyscall{
			Names:    syscall.Names,
			Action:   rspec.LinuxSeccompAction(syscall.Action),
			ErrnoRet: errnoRet,
			Args:     ToOCILinuxSeccompArgs(syscall.Args),
		})
	}

	return syscalls
}

func ToOCILinuxSeccompArgs(o []*LinuxSeccompArg) []rspec.LinuxSeccompArg {
	args := []rspec.LinuxSeccompArg{}

	for _, arg := range o {
		args = append(args, rspec.LinuxSeccompArg{
			Index:    uint(arg.Index),
			Value:    arg.Value,
			ValueTwo: arg.ValueTwo,
			Op:       rspec.LinuxSeccompOperator(arg.Op),
		})
	}

	return args
}
