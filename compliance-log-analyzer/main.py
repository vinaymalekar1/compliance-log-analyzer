"""ASGI entry point:  uvicorn main:app --reload"""
from analyzer.api import create_app

app = create_app()
