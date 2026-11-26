import io
import json
import unittest
import uuid

from fastapi import UploadFile
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.main import import_zap, assessment_report, verify_finding, verify_finding_api, VerificationRequest, ApiVerificationRequest
from app.models import Finding, Target

class ZapImportTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        @event.listens_for(self.engine, "connect")
        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")
        Base.metadata.create_all(self.engine)
        self.session = sessionmaker(bind=self.engine, expire_on_commit=False)()
        self.target = Target(id=str(uuid.uuid4()), name="Local test", url="https://93.184.216.34/app",
                             owner_contact="owner", in_scope=["https://93.184.216.34/app"],
                             out_of_scope=["https://93.184.216.34/app/private"], authorization_confirmed=True)
        self.session.add(self.target)
        self.session.commit()

    def tearDown(self):
        self.session.close()
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()

    def test_import_filters_scope_and_report_uses_confirmed_only(self):
        report = {"site":[{"alerts":[
            {"alert":"Missing security header","name":"Configuration","risk":"Low","description":"Header is missing.",
             "solution":"Add the header.","cweid":"693","instances":[{"uri":"https://93.184.216.34/app/home","evidence":"Header absent"}]},
            {"alert":"Cookie observation","name":"Session Management","risk":"Informational","description":"Cookie requires review.",
             "solution":"Review cookie flags.","instances":[{"uri":"https://93.184.216.34/app/login","evidence":"Set-Cookie observed"}]},
            {"alert":"Out of scope","name":"Other","risk":"High","instances":[{"uri":"https://93.184.216.34/app/private/account"}]}
            ,{"alert":"Encoded traversal","name":"Other","risk":"High","instances":[{"uri":"https://93.184.216.34/app/%252e%252e/private"}]}
        ]}]}
        file = UploadFile(filename="zap.json", file=io.BytesIO(json.dumps(report).encode()))
        imported = import_zap(self.target.id, file, self.session)
        self.assertEqual(imported["findings_imported"], 2)
        self.assertEqual(imported["instances_skipped_outside_scope"], 2)
        findings = self.session.scalars(select(Finding).order_by(Finding.title)).all()
        finding = next(item for item in findings if item.title == "Missing security header")
        self.assertEqual(finding.verification, "needs_review")
        self.assertEqual(finding.scanner_observation["risk"], "Low")
        self.assertEqual(imported["confirmed_findings"], 0)

        with self.assertRaises(Exception):
            verify_finding(finding.id, VerificationRequest(verification="confirmed"), self.session)
        decision = verify_finding(finding.id, VerificationRequest(
            verification="confirmed", assessor_severity="medium", comment="Evidence reviewed."
        ), self.session)
        self.assertEqual(decision["verification"], "confirmed")
        response = assessment_report(imported["scan_id"], self.session)
        self.assertIn(b"Missing security header", response.body)
        self.assertIn(b"confirmed vulnerabilities", response.body.lower())
        self.assertNotIn(b"Cookie observation", response.body)

    def test_import_normalizes_risk_and_redacts_sensitive_values_before_storage(self):
        report = {"site":[{"alerts":[
            {"alert":"Cookie issue", "name":"Session", "riskdesc":"High (Medium)",
             "desc":"Contact user@example.com; Authorization: Bearer abc123 and session=secretvalue",
             "instances":[{"uri":"https://93.184.216.34/app/home?token=secretvalue", "evidence":"Cookie: sid=privatevalue"}]}
        ]}]}
        file = UploadFile(filename="zap.json", file=io.BytesIO(json.dumps(report).encode()))
        imported = import_zap(self.target.id, file, self.session)
        finding = self.session.scalars(select(Finding)).one()
        self.assertEqual(imported["findings_imported"], 1)
        self.assertEqual(finding.scanner_severity, "high")
        self.assertEqual(finding.risk_level, "High")
        self.assertEqual(finding.status, "Needs Review")
        self.assertEqual(finding.target_url, self.target.url)
        self.assertIn("[REDACTED_EMAIL]", finding.description)
        self.assertNotIn("user@example.com", finding.description)
        self.assertNotIn("abc123", finding.description)
        self.assertNotIn("secretvalue", finding.description)
        self.assertNotIn("privatevalue", finding.evidence)
        saved_scan = self.session.get(__import__("app.models", fromlist=["Scan"]).Scan, imported["scan_id"])
        self.assertNotIn("secretvalue", json.dumps(saved_scan.raw_output))

    def test_compatibility_verification_endpoint_saves_assessor_decision(self):
        report = {"site":[{"alerts":[{"alert":"Header issue", "risk":"Medium",
                 "instances":[{"uri":"https://93.184.216.34/app/home"}]}]}]}
        import_zap(self.target.id, UploadFile(filename="zap.json", file=io.BytesIO(json.dumps(report).encode())), self.session)
        finding = self.session.scalars(select(Finding)).one()
        result = verify_finding_api(finding.id, ApiVerificationRequest(action="Confirm", severity_override="High"), self.session)
        self.assertEqual(result["message"], "Finding confirmed")
        self.assertEqual(result["finding"]["status"], "Confirmed")
        self.assertEqual(result["finding"]["severity_override"], "high")

if __name__ == "__main__":
    unittest.main()
