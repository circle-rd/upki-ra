"""
uPKI RA Server - Correlation Graph API Schemas.

Generic node/edge shape for `GET /graph?root=type:id` (see
uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §5), distinct from the
CA-hierarchy-specific `CAGraph`/`CAGraphEdge` in `cas.py`.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from .common import CamelModel

GraphNodeType = Literal["certificate", "ca", "profile", "csr"]


class GraphNode(CamelModel):
    """A single node in a correlation graph, e.g. ``certificate:AA:BB:CC``."""

    id: str
    type: GraphNodeType
    label: str
    data: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(CamelModel):
    """A directed, labeled edge between two `GraphNode.id` values."""

    source: str
    target: str
    relation: str


class Graph(CamelModel):
    """Nodes + edges for the `/graph` correlation endpoint."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]
