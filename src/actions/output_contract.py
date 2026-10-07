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
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from soar_sdk.action_results import OutputFieldSpecification


@dataclass(frozen=True, slots=True)
class LegacyOutputField:
    """A stable legacy datapath that cannot be represented by one output model."""

    data_path: str
    contains: tuple[str, ...] = ()
    example_values: tuple[object, ...] = ()

    def as_specification(self, parent_datapath: str) -> OutputFieldSpecification:
        specification = OutputFieldSpecification(
            data_path=f"{parent_datapath}.{self.data_path}",
            data_type="string",
        )
        if self.contains:
            specification["contains"] = list(self.contains)
        if self.example_values:
            specification["example_values"] = list(self.example_values)
        return specification


def append_legacy_fields(
    generated_fields: Iterable[OutputFieldSpecification],
    parent_datapath: str,
    legacy_fields: tuple[LegacyOutputField, ...],
) -> Iterator[OutputFieldSpecification]:
    """Append non-duplicated compatibility fields to an SDK-generated schema."""
    generated_fields = tuple(generated_fields)
    existing_paths = {field["data_path"] for field in generated_fields}
    yield from generated_fields

    for legacy_field in legacy_fields:
        specification = legacy_field.as_specification(parent_datapath)
        if specification["data_path"] not in existing_paths:
            yield specification
