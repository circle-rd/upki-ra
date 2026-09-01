"""
uPKI RA Server - OpenAPI Schema Sanity Tests.

Guards the contract Phase 2's TypeScript codegen depends on directly (see
uPKI-app/docs/ROADMAP.md, lot 1.8): no duplicate operationIds (breaks most
codegen tools, which key generated method names off of them) and no
untyped/empty "object" schema leaks (produces useless `any`-shaped types).
"""

import importlib.util
import os
import tempfile
import unittest

from upki_ra.core.upki_logger import UPKILogger
from upki_ra.registration_authority import RegistrationAuthority

_RA_SERVER_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ra_server.py")


def _load_openapi_schema() -> dict:
    spec = importlib.util.spec_from_file_location("ra_server", _RA_SERVER_PATH)
    ra_server = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ra_server)

    temp_dir = tempfile.mkdtemp()
    ra = RegistrationAuthority(data_dir=temp_dir, logger=UPKILogger(name="openapi-schema-test"))
    app = ra_server.create_app(ra)
    return app.openapi()


class TestOpenAPISchema(unittest.TestCase):
    """Test cases validating the generated OpenAPI schema is codegen-friendly."""

    @classmethod
    def setUpClass(cls):
        cls.schema = _load_openapi_schema()

    def test_schema_generates_without_error(self):
        self.assertIn("paths", self.schema)
        self.assertIn("components", self.schema)

    def test_inventory_paths_are_present(self):
        inventory_paths = [p for p in self.schema["paths"] if "/inventory" in p]
        self.assertGreaterEqual(len(inventory_paths), 20)

    def test_no_duplicate_operation_ids(self):
        operation_ids = [
            operation["operationId"]
            for methods in self.schema["paths"].values()
            for operation in methods.values()
            if isinstance(operation, dict) and "operationId" in operation
        ]
        duplicates = {op_id for op_id in operation_ids if operation_ids.count(op_id) > 1}
        self.assertEqual(duplicates, set(), f"Duplicate operationIds found: {duplicates}")

    def test_every_operation_has_an_operation_id(self):
        missing = [
            (path, method)
            for path, methods in self.schema["paths"].items()
            for method, operation in methods.items()
            if isinstance(operation, dict) and "operationId" not in operation
        ]
        self.assertEqual(missing, [])

    def test_no_untyped_empty_object_schemas(self):
        schemas = self.schema.get("components", {}).get("schemas", {})
        suspicious = [
            name
            for name, s in schemas.items()
            if s.get("type") == "object"
            and not s.get("properties")
            and "additionalProperties" not in s
            and "allOf" not in s
            and "anyOf" not in s
        ]
        self.assertEqual(suspicious, [], f"Untyped/empty object schemas: {suspicious}")

    def test_inventory_endpoints_use_typed_success_response(self):
        """Every /inventory GET/POST/PUT response should $ref a real schema,
        not fall back to a bare, untyped "object" (verifies `response_model`
        was set - see inventory_api.py)."""
        for path, methods in self.schema["paths"].items():
            if "/inventory" not in path or path.endswith("/ws"):
                continue
            for method, operation in methods.items():
                if method not in ("get", "post", "put", "delete"):
                    continue
                responses = operation.get("responses", {})
                success = responses.get("200") or responses.get("201")
                if not success:
                    continue
                content = success.get("content", {}).get("application/json", {})
                schema_ref = content.get("schema", {})
                self.assertTrue(
                    "$ref" in schema_ref or "allOf" in schema_ref or schema_ref.get("type") != "object",
                    f"{method.upper()} {path} has an untyped response schema: {schema_ref}",
                )


if __name__ == "__main__":
    unittest.main()
