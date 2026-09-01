"""
uPKI RA Server - Shared API Schema Primitives.

Base model and response envelope shared by every REST resource schema in
`upki_ra.schemas`. These models are the single source of truth for the RA's
OpenAPI contract (see uPKI-app/docs/ROADMAP.md, "shared types" decision):
`uPKI-app` generates its TypeScript types from `/openapi.json`, so field
names/shapes here should be treated as a public API and changed carefully.
"""

from __future__ import annotations

from typing import Generic, Literal, Self, TypeVar

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

T = TypeVar("T")


class CamelModel(BaseModel):
    """Base model serializing/deserializing with camelCase JSON keys.

    Python attribute names stay snake_case (PEP 8); `alias_generator` maps
    them to camelCase on the wire so the JSON shape matches `Upkiweb`'s
    existing TypeScript types (e.g. `valid_to` <-> `validTo`). Fields whose
    desired camelCase form isn't a plain single-capital transform (e.g.
    acronyms like `CSR`/`OID`) declare an explicit `Field(alias=...)`, which
    takes precedence over the generator.
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class PaginatedData(CamelModel, Generic[T]):
    """Generic ``{items, page, pageSize, total, totalPages}`` list payload."""

    items: list[T]
    page: int
    page_size: int
    total: int
    total_pages: int

    @classmethod
    def build(cls, items: list[T], total: int, page: int, page_size: int) -> Self:
        """Build a paginated payload, deriving ``total_pages`` from ``total``/``page_size``."""
        total_pages = max(1, (total + page_size - 1) // page_size) if page_size else 1
        return cls(items=items, page=page, page_size=page_size, total=total, total_pages=total_pages)


class SuccessResponse(CamelModel, Generic[T]):
    """``{"status": "success", "data": ...}`` envelope.

    Matches the JSON shape already produced by `upki_ra.utils.common.format_response`
    for the pre-existing routes, but with a concrete typed `data` payload so
    FastAPI's generated OpenAPI schema (and thus the codegen'd frontend
    types) are precise instead of an opaque `object`.
    """

    status: Literal["success"] = "success"
    data: T


class ErrorResponse(BaseModel):
    """``{"status": "error", "code": ..., "message": ...}`` envelope.

    Matches `upki_ra.utils.common.format_error`.
    """

    status: Literal["error"] = "error"
    code: str
    message: str
