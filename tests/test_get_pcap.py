# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from src.actions.get_pcap import _platform_attempts


def test_platform_attempts_preserve_legacy_windows_xp_fallbacks() -> None:
    assert _platform_attempts(2) == (2, 60, 20)


def test_platform_attempts_preserve_legacy_windows_7_fallback() -> None:
    assert _platform_attempts(5) == (5, 61)


def test_platform_attempts_leave_other_platforms_unchanged() -> None:
    assert _platform_attempts(66) == (66,)
    assert _platform_attempts(None) == (None,)
