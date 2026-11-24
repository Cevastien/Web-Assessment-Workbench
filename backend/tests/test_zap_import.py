import io
import json
import unittest
import uuid

from fastapi import UploadFile
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.main import import_zap, assessment_report, verify_finding, VerificationRequest
from app.models import Finding, Target

class ZapImportTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
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

if __name__ == "__main__":
    unittest.main()
