// Copyright 2023 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package protocol

import "fmt"

// Version indicates the version of the Roughtime protocol in use.
type Version uint32

const (
	// VersionGoogle is Google-Roughtime as described here:
	// https://roughtime.googlesource.com/roughtime/+/HEAD/PROTOCOL.md
	VersionGoogle Version = 0

	// VersionDraft08 is draft-ietf-ntp-roughtime-08
	VersionDraft08 Version = 0x80000008
)

// allVersions is a list of all supported versions in order from newest to oldest.
var allVersions = []Version{
	VersionDraft08,
	VersionGoogle,
}

// ietfVersions is a list of all IETF drafts in order from newest to oldest.
var ietfVersions = []Version{
	VersionDraft08,
}

func (ver Version) isSupported() bool {
	for i := range ietfVersions {
		if ver == ietfVersions[i] {
			return true
		}
	}
	return false
}

func (ver Version) String() string {
	switch ver {
	case VersionGoogle:
		return "Google-Roughtime"
	case VersionDraft08:
		return "draft-ietf-ntp-roughtime-08"
	default:
		return fmt.Sprintf("%d", uint32(ver))
	}
}

// advertisedVersionsFromPreference derives the list of versions advertised in
// its request by a client with the given preferences.
//
// If len(versionPreference) == 0, then a safe default is used.
//
// If versionPreference includes Google-Roughtime, then it must be the only
// version that is supported. If not, an error is returned.
//
// This function also returns a boolean indicating whether to use
// IETF-Roughtime.
func advertisedVersionsFromPreference(versionPreference []Version) ([]Version, bool, error) {
	if len(versionPreference) == 0 {
		return []Version{VersionDraft08}, true, nil
	}

	versionIETF := true
	for _, vers := range versionPreference {
		if vers == VersionGoogle {
			versionIETF = false
			break
		}
	}
	if !versionIETF && len(versionPreference) != 1 {
		return nil, false, fmt.Errorf("cannot support %s simultaneously with other versions", VersionGoogle)
	}

	return versionPreference, versionIETF, nil
}

// ResponseVersionFromSupported selects a version to use from the list of
// versions supported by the clients. Returns an error if the input slice is
// zero-length.
func ResponseVersionFromSupported(supportedVersions []Version) (Version, error) {
	for _, ver := range allVersions {
		for _, supportedVer := range supportedVersions {
			if ver == supportedVer {
				return ver, nil
			}
		}
	}
	return 0, errUnsupportedVersion(supportedVersions)
}
