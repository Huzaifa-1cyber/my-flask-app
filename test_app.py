import pytest
from app import app

@pytest.fixture
def client():
    app.testing = True
    with app.test_client() as client:
        yield client

def test_home_page(client):
    """
    Test if home page loads successfully
    """
    response = client.get('/')
    assert response.status_code == 200

def test_home_page_content(client):
    """
    Test if expected content is present in response
    """
    response = client.get('/')
    assert b"Hello" in response.data or b"Flask" in response.data
