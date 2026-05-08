import os
import secrets


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # KGC authority token — used to authorise identity-tracing requests
    KGC_AUTHORITY_TOKEN = os.environ.get("KGC_AUTHORITY_TOKEN", "kgc-admin-secret-change-in-prod")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024   # 16 MB upload limit


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///cls_healthcare.db"


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret"
    KGC_AUTHORITY_TOKEN = "test-kgc-token"


class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///cls_healthcare.db"
    )
