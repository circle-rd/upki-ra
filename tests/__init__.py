"""
uPKI RA Server - Unit Tests.

Unit tests for the uPKI RA Server components.
"""

import unittest


def suite():
    """Create test suite for all tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test modules
    from . import test_core, test_routes, test_utils

    suite.addTests(loader.loadTestsFromModule(test_core))
    suite.addTests(loader.loadTestsFromModule(test_utils))
    suite.addTests(loader.loadTestsFromModule(test_routes))

    return suite


if __name__ == "__main__":
    unittest.main()
