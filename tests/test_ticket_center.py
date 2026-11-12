import os
import tempfile
import unittest

os.environ.setdefault("VTAB_TICKET_SIGNING_SECRET", "test-secret-that-is-long-enough-for-unit-tests")

from fastapi import HTTPException
from app.security import sign_payload, verify_payload
from app.state_machine import validate_transition


class TicketLifecycleTests(unittest.TestCase):
    def test_diagnostic_token_round_trip(self):
        token = sign_payload({"kind": "diagnostic", "app_version": "6.1.16"}, 60)
        self.assertEqual(verify_payload(token)["app_version"], "6.1.16")

    def test_developer_cannot_close(self):
        with self.assertRaises(HTTPException):
            validate_transition("PENDING_ADMIN_SIGN_OFF", "CLOSED", "developer", {"user_experience_verified": True, "notes": "tested"})

    def test_resolution_requires_build_commit_and_notes(self):
        with self.assertRaises(HTTPException):
            validate_transition("IN_PROGRESS", "PENDING_ADMIN_SIGN_OFF", "developer", {"notes": "done"})

    def test_admin_close_requires_verification(self):
        with self.assertRaises(HTTPException):
            validate_transition("PENDING_ADMIN_SIGN_OFF", "CLOSED", "admin", {"notes": "tested", "user_experience_verified": False})
        validate_transition("PENDING_ADMIN_SIGN_OFF", "CLOSED", "admin", {"notes": "tested", "user_experience_verified": True})

    def test_reopen_requires_feedback(self):
        with self.assertRaises(HTTPException):
            validate_transition("PENDING_ADMIN_SIGN_OFF", "REOPENED", "admin", {"notes": ""})


if __name__ == "__main__":
    unittest.main()

