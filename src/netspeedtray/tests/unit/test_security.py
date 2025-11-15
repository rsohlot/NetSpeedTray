"""
Unit tests for security features in the NetSpeedTray application.

Tests input validation, SQL injection prevention, and database integrity checks.
"""
import pytest
import tempfile
import sqlite3
from pathlib import Path
from datetime import datetime
from netspeedtray.utils.db_utils import (
    validate_interface_name,
    validate_app_name,
    sanitize_interface_list,
    sanitize_app_list,
    verify_database_integrity,
    calculate_database_checksum,
    init_database
)
from netspeedtray import constants


class TestInputValidation:
    """Test suite for input validation functions"""
    
    def test_validate_interface_name_accepts_valid_names(self):
        """Valid interface names should be accepted"""
        valid_names = [
            "Wi-Fi",
            "Ethernet",
            "Local Area Connection",
            "VPN Connection",
            "Bluetooth Network Connection"
        ]
        for name in valid_names:
            assert validate_interface_name(name) is True, f"Should accept valid name: {name}"
    
    def test_validate_interface_name_rejects_sql_injection(self):
        """SQL injection attempts should be rejected"""
        sql_injection_attempts = [
            "'; DROP TABLE speed_history; --",
            "' OR '1'='1",
            "Wi-Fi'; DELETE FROM speed_history WHERE '1'='1",
            "\" OR \"1\"=\"1",
            "'; DROP TABLE speed_history; --",
            "' UNION SELECT * FROM passwords; --",
            "admin'--",
        ]
        for attempt in sql_injection_attempts:
            assert validate_interface_name(attempt) is False, f"Should reject SQL injection: {attempt}"
    
    def test_validate_interface_name_rejects_malformed_input(self):
        """Malformed inputs should be rejected"""
        assert validate_interface_name("") is False  # Empty string
        assert validate_interface_name(None) is False  # None
        assert validate_interface_name("A" * 257) is False  # Too long
        assert validate_interface_name("Wi-Fi\x00") is False  # Null byte
        assert validate_interface_name("Test\x01") is False  # Control character
    
    def test_validate_interface_name_accepts_edge_cases(self):
        """Edge cases that should be valid"""
        assert validate_interface_name("Wi-Fi 📡") is True  # Unicode/emoji
        assert validate_interface_name("A" * 256) is True  # Max length
        assert validate_interface_name("Test-Connection_123") is True  # Special chars


class TestAppNameValidation:
    """Test suite for application name validation"""
    
    def test_validate_app_name_accepts_valid_names(self):
        """Valid app names should be accepted"""
        valid_names = [
            "chrome.exe",
            "firefox.exe",
            "Visual Studio Code.exe",
            "Python 3.11.exe"
        ]
        for name in valid_names:
            assert validate_app_name(name) is True, f"Should accept valid name: {name}"
    
    def test_validate_app_name_rejects_sql_injection(self):
        """SQL injection attempts in app names should be rejected"""
        sql_injection_attempts = [
            "'; DROP TABLE app_bandwidth; --",
            "app.exe'; DELETE FROM app_bandwidth WHERE '1'='1",
            "' OR '1'='1",
        ]
        for attempt in sql_injection_attempts:
            assert validate_app_name(attempt) is False, f"Should reject SQL injection: {attempt}"
    
    def test_validate_app_name_rejects_malformed_input(self):
        """Malformed app names should be rejected"""
        assert validate_app_name("") is False  # Empty string
        assert validate_app_name(None) is False  # None
        assert validate_app_name("A" * 513) is False  # Too long
        assert validate_app_name("app.exe\x00") is False  # Null byte


class TestListSanitization:
    """Test suite for list sanitization functions"""
    
    def test_sanitize_interface_list_filters_malicious_entries(self):
        """Malicious interface names should be filtered out"""
        malicious_list = [
            "Wi-Fi",
            "'; DROP TABLE speed_history; --",
            "Ethernet",
            "' OR '1'='1"
        ]
        result = sanitize_interface_list(malicious_list)
        assert len(result) == 2
        assert "Wi-Fi" in result
        assert "Ethernet" in result
        assert "'; DROP TABLE speed_history; --" not in result
    
    def test_sanitize_interface_list_handles_empty_input(self):
        """Empty or None input should return empty list"""
        assert sanitize_interface_list([]) == []
        assert sanitize_interface_list(None) == []
    
    def test_sanitize_interface_list_preserves_all_valid_entries(self):
        """All valid entries should be preserved"""
        valid_list = ["Wi-Fi", "Ethernet", "VPN", "Bluetooth"]
        result = sanitize_interface_list(valid_list)
        assert len(result) == 4
        assert result == valid_list
    
    def test_sanitize_app_list_filters_malicious_entries(self):
        """Malicious app names should be filtered out"""
        malicious_list = [
            "chrome.exe",
            "'; DELETE FROM app_bandwidth; --",
            "firefox.exe"
        ]
        result = sanitize_app_list(malicious_list)
        assert len(result) == 2
        assert "chrome.exe" in result
        assert "firefox.exe" in result
    
    def test_sanitize_app_list_handles_empty_input(self):
        """Empty or None input should return empty list"""
        assert sanitize_app_list([]) == []
        assert sanitize_app_list(None) == []


class TestDatabaseIntegrity:
    """Test suite for database integrity checks"""
    
    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database file for testing"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = Path(f.name)
        yield db_path
        # Cleanup - handle Windows file locking
        import time
        import gc
        gc.collect()  # Force garbage collection to close any open connections
        time.sleep(0.1)  # Brief delay for Windows to release file handles
        try:
            if db_path.exists():
                db_path.unlink()
            # Also clean up any backup files created during tests
            for backup in db_path.parent.glob(f"{db_path.name}.corrupted.*"):
                try:
                    backup.unlink()
                except (PermissionError, FileNotFoundError):
                    pass
        except (PermissionError, FileNotFoundError):
            pass  # Ignore if file is still locked or already deleted
    
    def test_verify_database_integrity_rejects_missing_file(self):
        """Should reject non-existent database file"""
        fake_path = Path("/tmp/nonexistent_database.db")
        is_valid, error_msg = verify_database_integrity(fake_path)
        assert is_valid is False
        assert "does not exist" in error_msg
    
    def test_verify_database_integrity_rejects_empty_file(self, temp_db_path):
        """Should reject empty or too small database file"""
        # Create empty file
        temp_db_path.write_bytes(b"")
        is_valid, error_msg = verify_database_integrity(temp_db_path)
        assert is_valid is False
        assert "too small" in error_msg
    
    def test_verify_database_integrity_accepts_valid_database(self, temp_db_path):
        """Should accept a properly initialized database"""
        # Initialize a valid database
        init_database(temp_db_path)
        is_valid, error_msg = verify_database_integrity(temp_db_path)
        assert is_valid is True
        assert error_msg == ""
    
    def test_verify_database_integrity_detects_missing_tables(self, temp_db_path):
        """Should detect if required tables are missing"""
        # Create a valid SQLite database but without our tables
        with sqlite3.connect(temp_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE some_other_table (id INTEGER)")
            conn.commit()
        
        is_valid, error_msg = verify_database_integrity(temp_db_path)
        assert is_valid is False
        assert "Missing required tables" in error_msg
    
    def test_calculate_database_checksum_returns_valid_hash(self, temp_db_path):
        """Should return a valid SHA-256 checksum"""
        init_database(temp_db_path)
        checksum = calculate_database_checksum(temp_db_path)
        assert checksum is not None
        assert len(checksum) == 64  # SHA-256 hex string length
        assert all(c in '0123456789abcdef' for c in checksum)
    
    def test_calculate_database_checksum_is_consistent(self, temp_db_path):
        """Same file should produce same checksum"""
        init_database(temp_db_path)
        checksum1 = calculate_database_checksum(temp_db_path)
        checksum2 = calculate_database_checksum(temp_db_path)
        assert checksum1 == checksum2
    
    def test_init_database_handles_corrupted_database(self, temp_db_path):
        """Should backup and recreate corrupted database"""
        # Create a corrupted database (invalid SQLite file)
        temp_db_path.write_bytes(b"This is not a valid SQLite database file!!!")
        
        # Initialize should handle this gracefully
        init_database(temp_db_path)
        
        # Check that a backup was created
        backup_files = list(temp_db_path.parent.glob(f"{temp_db_path.name}.corrupted.*"))
        assert len(backup_files) > 0
        
        # Check that new database is valid
        is_valid, _ = verify_database_integrity(temp_db_path)
        assert is_valid is True
        
        # Cleanup backup
        for backup in backup_files:
            backup.unlink()


class TestSQLInjectionPrevention:
    """Integration tests to ensure SQL injection is prevented end-to-end"""
    
    def test_sql_injection_blocked_in_parameterized_queries(self):
        """Verify that parameterized queries prevent SQL injection"""
        # Common SQL injection patterns
        dangerous_inputs = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM passwords; --",
            "admin'--",
            "1'; DELETE FROM table WHERE '1'='1'; --",
        ]
        
        for dangerous_input in dangerous_inputs:
            # These should be filtered out by validation
            assert validate_interface_name(dangerous_input) is False
            assert validate_app_name(dangerous_input) is False
            
            # And sanitization should remove them from lists
            result = sanitize_interface_list([dangerous_input])
            assert len(result) == 0


if __name__ == "__main__":
    # Allow running this test file directly
    pytest.main([__file__, "-v"])

