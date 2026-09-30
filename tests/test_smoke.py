import os
os.environ.setdefault("APP_ENV","development")
os.environ.setdefault("SECRET_KEY","test")
os.environ.setdefault("DATABASE_URL","sqlite:////tmp/hopefli-test.db")
os.environ.setdefault("REDIS_URL","redis://localhost:6379/15")
from app import create_app

def test_health():
    app=create_app(); app.config.update(TESTING=True)
    with app.test_client() as c:
        r=c.get('/health')
        assert r.status_code==200
        assert r.get_json()['status']=='ok'
