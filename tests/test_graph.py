"""
uPKI RA Server - Correlation Graph Service Unit Tests.
"""

import shutil
import tempfile
import unittest

from upki_ra.services.graph import GraphRootNotFoundError, UnknownGraphRootError, build_graph
from upki_ra.storage import InventoryStorage


class TestBuildGraph(unittest.TestCase):
    """Test cases for `build_graph`."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _seed_ca(self, **overrides):
        ca = {
            "id": "ca-1",
            "name": "Root CA",
            "type": "root",
            "status": "active",
            "subject": "CN=Root CA",
            "valid_from": "2020-01-01T00:00:00Z",
            "valid_to": "2030-01-01T00:00:00Z",
        }
        ca.update(overrides)
        self.storage.upsert_ca(ca)
        return ca

    def _seed_profile(self, **overrides):
        self.storage.upsert_profile(
            overrides.pop("id", "prof-1"),
            overrides.pop("name", "Web Server"),
            overrides.pop("description", ""),
            overrides,
        )

    def _seed_cert(self, **overrides):
        cert = {
            "serial": "s1",
            "dn": "CN=example.com",
            "common_name": "example.com",
            "key_type": "RSA-2048",
            "status": "valid",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_to": "2030-01-01T00:00:00Z",
        }
        cert.update(overrides)
        self.storage.upsert_certificate(cert)
        return cert

    def test_invalid_root_format(self):
        with self.assertRaises(UnknownGraphRootError):
            build_graph(self.storage, "no-colon-here")

    def test_unknown_root_type(self):
        with self.assertRaises(UnknownGraphRootError):
            build_graph(self.storage, "widget:1")

    def test_certificate_not_found(self):
        with self.assertRaises(GraphRootNotFoundError):
            build_graph(self.storage, "certificate:nope")

    def test_certificate_root_minimal(self):
        self._seed_cert()
        graph = build_graph(self.storage, "certificate:s1")
        self.assertEqual([n.id for n in graph.nodes], ["certificate:s1"])
        self.assertEqual(graph.edges, [])

    def test_certificate_root_with_ca_and_profile(self):
        self._seed_ca()
        self._seed_profile()
        self._seed_cert(ca_id="ca-1", profile_id="prof-1")

        graph = build_graph(self.storage, "certificate:s1")
        node_ids = {n.id for n in graph.nodes}
        self.assertEqual(node_ids, {"certificate:s1", "ca:ca-1", "profile:prof-1"})
        relations = {(e.source, e.target, e.relation) for e in graph.edges}
        self.assertIn(("ca:ca-1", "certificate:s1", "issued"), relations)
        self.assertIn(("certificate:s1", "profile:prof-1", "uses_profile"), relations)

    def test_certificate_root_with_originating_csr(self):
        self._seed_cert(serial="s1", common_name="csr-origin.example.com")
        csr_id = self.storage.create_csr(
            {"subject": "csr-origin.example.com", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----"}
        )
        self.storage.resolve_csr(csr_id, "approved", "admin@example.com", certificate_serial="s1")

        graph = build_graph(self.storage, "certificate:s1")
        node_ids = {n.id for n in graph.nodes}
        self.assertIn(f"csr:{csr_id}", node_ids)
        relations = {(e.source, e.target, e.relation) for e in graph.edges}
        self.assertIn((f"csr:{csr_id}", "certificate:s1", "originated"), relations)

    def test_certificate_root_with_renewal_chain(self):
        self._seed_cert(serial="s1", common_name="renew.example.com")
        self._seed_cert(serial="s2", common_name="renew.example.com")
        self._seed_cert(serial="s3", common_name="renew.example.com")

        graph = build_graph(self.storage, "certificate:s2")
        node_ids = {n.id for n in graph.nodes}
        self.assertEqual(node_ids, {"certificate:s1", "certificate:s2", "certificate:s3"})
        relations = {(e.source, e.target, e.relation) for e in graph.edges}
        self.assertIn(("certificate:s1", "certificate:s2", "renewed_to"), relations)
        self.assertIn(("certificate:s2", "certificate:s3", "renewed_to"), relations)

    def test_ca_not_found(self):
        with self.assertRaises(GraphRootNotFoundError):
            build_graph(self.storage, "ca:nope")

    def test_ca_root_with_parent_and_children(self):
        self._seed_ca(id="ca-root")
        self._seed_ca(id="ca-mid", parent_id="ca-root")
        self._seed_ca(id="ca-leaf", parent_id="ca-mid")

        graph = build_graph(self.storage, "ca:ca-mid")
        node_ids = {n.id for n in graph.nodes}
        self.assertEqual(node_ids, {"ca:ca-root", "ca:ca-mid", "ca:ca-leaf"})
        relations = {(e.source, e.target, e.relation) for e in graph.edges}
        self.assertIn(("ca:ca-root", "ca:ca-mid", "parent_of"), relations)
        self.assertIn(("ca:ca-mid", "ca:ca-leaf", "parent_of"), relations)

    def test_profile_not_found(self):
        with self.assertRaises(GraphRootNotFoundError):
            build_graph(self.storage, "profile:nope")

    def test_profile_root_is_standalone(self):
        self._seed_profile()
        graph = build_graph(self.storage, "profile:prof-1")
        self.assertEqual([n.id for n in graph.nodes], ["profile:prof-1"])
        self.assertEqual(graph.edges, [])

    def test_csr_not_found(self):
        with self.assertRaises(GraphRootNotFoundError):
            build_graph(self.storage, "csr:nope")

    def test_csr_root_with_profile_and_resulting_certificate(self):
        self._seed_profile()
        self._seed_cert(serial="s1", common_name="csr-result.example.com")
        csr_id = self.storage.create_csr(
            {
                "subject": "csr-result.example.com",
                "profile_id": "prof-1",
                "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----",
            }
        )
        self.storage.resolve_csr(csr_id, "approved", "admin@example.com", certificate_serial="s1")

        graph = build_graph(self.storage, f"csr:{csr_id}")
        node_ids = {n.id for n in graph.nodes}
        self.assertEqual(node_ids, {f"csr:{csr_id}", "profile:prof-1", "certificate:s1"})


if __name__ == "__main__":
    unittest.main()
