"""
uPKI RA Server - Correlation Graph Service.

Builds a small neighborhood subgraph around a single entity (certificate,
CA, profile or CSR) for the generic `GET /graph?root=type:id` endpoint -
see uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §5. Distinct from
`InventoryStorage.get_ca_graph()`, which returns the *entire* CA hierarchy
rather than one entity's immediate neighborhood.
"""

from __future__ import annotations

from typing import Any

from ..schemas.graph import Graph, GraphEdge, GraphNode
from ..storage.inventory_storage import InventoryStorage


class UnknownGraphRootError(ValueError):
    """Raised when `root` isn't a recognized ``type:id`` reference."""


class GraphRootNotFoundError(ValueError):
    """Raised when `root` is well-formed but the entity doesn't exist."""


def _ca_node(ca: dict[str, Any]) -> GraphNode:
    return GraphNode(
        id=f"ca:{ca['id']}", type="ca", label=ca["name"], data={"type": ca["type"], "status": ca["status"]}
    )


def _profile_node(profile: dict[str, Any]) -> GraphNode:
    return GraphNode(id=f"profile:{profile['id']}", type="profile", label=profile["name"], data={})


def _csr_node(csr: dict[str, Any]) -> GraphNode:
    return GraphNode(
        id=f"csr:{csr['id']}", type="csr", label=csr["subject"], data={"status": csr["status"]}
    )


def _certificate_node(cert: dict[str, Any]) -> GraphNode:
    return GraphNode(
        id=f"certificate:{cert['serial']}",
        type="certificate",
        label=cert["common_name"],
        data={"status": cert["status"], "keyType": cert["key_type"]},
    )


def _build_certificate_graph(storage: InventoryStorage, serial: str) -> Graph:
    cert = storage.get_certificate(serial)
    if cert is None:
        raise GraphRootNotFoundError(f"Certificate not found: {serial}")

    root = _certificate_node(cert)
    nodes: list[GraphNode] = [root]
    edges: list[GraphEdge] = []

    if cert.get("ca_id"):
        ca = storage.get_ca(cert["ca_id"])
        if ca:
            ca_node = _ca_node(ca)
            nodes.append(ca_node)
            edges.append(GraphEdge(source=ca_node.id, target=root.id, relation="issued"))

    if cert.get("profile_id"):
        profile = storage.get_profile(cert["profile_id"])
        if profile:
            profile_node = _profile_node(profile)
            nodes.append(profile_node)
            edges.append(GraphEdge(source=root.id, target=profile_node.id, relation="uses_profile"))

    csr = storage.get_csr_by_certificate_serial(cert["serial"])
    if csr:
        csr_node = _csr_node(csr)
        nodes.append(csr_node)
        edges.append(GraphEdge(source=csr_node.id, target=root.id, relation="originated"))

    chain = storage.list_certificates_by_common_name(cert["common_name"])
    index = next((i for i, c in enumerate(chain) if c["serial"] == cert["serial"]), None)
    if index is not None:
        if index > 0:
            predecessor = _certificate_node(chain[index - 1])
            nodes.append(predecessor)
            edges.append(GraphEdge(source=predecessor.id, target=root.id, relation="renewed_to"))
        if index < len(chain) - 1:
            successor = _certificate_node(chain[index + 1])
            nodes.append(successor)
            edges.append(GraphEdge(source=root.id, target=successor.id, relation="renewed_to"))

    return Graph(nodes=nodes, edges=edges)


def _build_ca_graph(storage: InventoryStorage, ca_id: str) -> Graph:
    ca = storage.get_ca(ca_id)
    if ca is None:
        raise GraphRootNotFoundError(f"CA not found: {ca_id}")

    root = _ca_node(ca)
    nodes: list[GraphNode] = [root]
    edges: list[GraphEdge] = []

    if ca.get("parent_id"):
        parent = storage.get_ca(ca["parent_id"])
        if parent:
            parent_node = _ca_node(parent)
            nodes.append(parent_node)
            edges.append(GraphEdge(source=parent_node.id, target=root.id, relation="parent_of"))

    for other in storage.list_cas():
        if other.get("parent_id") == ca_id:
            child_node = _ca_node(other)
            nodes.append(child_node)
            edges.append(GraphEdge(source=root.id, target=child_node.id, relation="parent_of"))

    return Graph(nodes=nodes, edges=edges)


def _build_profile_graph(storage: InventoryStorage, profile_id: str) -> Graph:
    profile = storage.get_profile(profile_id)
    if profile is None:
        raise GraphRootNotFoundError(f"Profile not found: {profile_id}")
    # Profiles can fan out to a large number of certificates, which would
    # defeat the "small neighborhood" intent of this endpoint - return the
    # profile node on its own; certificate listing/filtering already covers
    # "which certs use this profile" (`GET /certificates?profile=...`).
    return Graph(nodes=[_profile_node(profile)], edges=[])


def _build_csr_graph(storage: InventoryStorage, csr_id: str) -> Graph:
    csr = storage.get_csr(csr_id)
    if csr is None:
        raise GraphRootNotFoundError(f"CSR not found: {csr_id}")

    root = _csr_node(csr)
    nodes: list[GraphNode] = [root]
    edges: list[GraphEdge] = []

    if csr.get("profile_id"):
        profile = storage.get_profile(csr["profile_id"])
        if profile:
            profile_node = _profile_node(profile)
            nodes.append(profile_node)
            edges.append(GraphEdge(source=root.id, target=profile_node.id, relation="uses_profile"))

    if csr.get("certificate_serial"):
        cert = storage.get_certificate(csr["certificate_serial"])
        if cert:
            cert_node = _certificate_node(cert)
            nodes.append(cert_node)
            edges.append(GraphEdge(source=root.id, target=cert_node.id, relation="originated"))

    return Graph(nodes=nodes, edges=edges)


_BUILDERS = {
    "certificate": _build_certificate_graph,
    "ca": _build_ca_graph,
    "profile": _build_profile_graph,
    "csr": _build_csr_graph,
}


def build_graph(storage: InventoryStorage, root: str) -> Graph:
    """Build a neighborhood subgraph around a single ``type:id`` entity.

    Args:
        storage: The RA's inventory storage.
        root: A reference like ``"certificate:AA:BB:CC"``, ``"ca:ca-1"``,
            ``"profile:prof-1"`` or ``"csr:csr-1"``.

    Returns:
        The neighborhood graph.

    Raises:
        UnknownGraphRootError: If `root` isn't ``type:id`` shaped or `type`
            isn't one of the supported entity types.
        GraphRootNotFoundError: If `root` is well-formed but no such entity
            exists.
    """
    if ":" not in root:
        raise UnknownGraphRootError(f"Invalid root reference: {root!r} (expected 'type:id')")

    node_type, node_id = root.split(":", 1)
    builder = _BUILDERS.get(node_type)
    if builder is None or not node_id:
        raise UnknownGraphRootError(f"Invalid root reference: {root!r} (expected 'type:id')")

    return builder(storage, node_id)
