import unittest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.main import TargetRequest, validate_target, validate_public_http_url

class TargetValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(cls.engine)
        cls.sessions = sessionmaker(bind=cls.engine, expire_on_commit=False)

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(cls.engine)
        cls.engine.dispose()

    def setUp(self):
        self.db = self.sessions()

    def tearDown(self):
        self.db.close()

    def test_requires_explicit_authorization(self):
        target = TargetRequest(name="Test target", url="https://example.test", owner_contact="owner",
                               authorized=False, in_scope=["https://example.test/"])
        with self.assertRaises(HTTPException) as raised:
            validate_target(target, self.db)
        self.assertEqual(raised.exception.status_code, 400)

    def test_blocks_localhost_and_loopback(self):
        for url in ("http://localhost", "http://127.0.0.1"):
            with self.subTest(url=url), self.assertRaises(HTTPException):
                validate_public_http_url(url)

    def test_requires_scope_to_match_target_host(self):
        target = TargetRequest(name="Test target", url="https://93.184.216.34", owner_contact="owner",
                               authorized=True, in_scope=["https://1.1.1.1/"])
        with self.assertRaises(HTTPException) as raised:
            validate_target(target, self.db)
        self.assertEqual(raised.exception.status_code, 422)

    def test_requires_scope_to_match_scheme_and_port(self):
        target = TargetRequest(name="Test target", url="https://93.184.216.34", owner_contact="owner",
                               authorized=True, in_scope=["http://93.184.216.34/"])
        with self.assertRaises(HTTPException) as raised:
            validate_target(target, self.db)
        self.assertEqual(raised.exception.status_code, 422)

    def test_persists_authorized_target_with_matching_scope(self):
        target = TargetRequest(name="Test target", url="https://93.184.216.34", owner_contact="owner",
                               authorized=True, in_scope=["https://93.184.216.34/"])
        result = validate_target(target, self.db)
        self.assertTrue(result["valid"])
        self.assertEqual(result["target"]["in_scope"], ["https://93.184.216.34/"])
        self.assertEqual(len(self.db.query(__import__("app.models", fromlist=["Target"]).Target).all()), 1)

if __name__ == "__main__":
    unittest.main()
