from sentinelmail.validation import validate_and_normalize, InvalidEmailError
import pytest

def test_valid_email():
    email, local, domain = validate_and_normalize("User@Example.com")
    assert domain == "example.com"
    assert local == "User"
    assert email == "User@example.com"

def test_invalid_email():
    with pytest.raises(InvalidEmailError):
        validate_and_normalize("not-an-email")
