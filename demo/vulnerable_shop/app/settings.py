import os

DEBUG = True
ALLOWED_HOSTS = ["*"]
SECRET_KEY = "django-insecure-8f3k2mQp9vXz1LwR7tYb4NcH6JdGsA0e"
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
CORS_ALLOW_ALL_ORIGINS = True
CSRF_COOKIE_SECURE = False
AWS_ACCESS_KEY_ID = "AKIA4XQ7ZM2NPBWLKC3D"
AWS_SECRET_ACCESS_KEY = "hT9vKq2LpXn4RwZ6bYs8Dm1AcVg0FjUeQi5NoPtR"
# The line below is AWS's published documentation key - secscan should notice.
AWS_DOCS_EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"
UPSTREAM = "http://payments.internal.example.com/charge"
