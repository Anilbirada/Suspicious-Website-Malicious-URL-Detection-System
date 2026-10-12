"""FastAPI application entry point for the Suspicious Website / Malicious URL Detection System.

Developed by Anil Biradar.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router as api_v1_router
from app.core.config import Settings, settings
from app.ml.inference import MLModelService
from app.models.database import create_engine_from_url, init_db
from app.services.analyzer_service import URLAnalyzerOrchestrator
from sqlalchemy.orm import sessionmaker


def create_app(custom_settings: Optional[Settings] = None) -> FastAPI:
    """Application factory supporting isolated configuration for testing and production."""
    active_settings = custom_settings or settings
    app_engine = create_engine_from_url(active_settings.database_url)
    app_session_factory = sessionmaker(
        bind=app_engine, autoflush=False, autocommit=False, expire_on_commit=False
    )
    init_db(app_engine)

    @asynccontextmanager
    async def lifespan(_app_instance: FastAPI):
        init_db(app_engine)
        yield

    app = FastAPI(
        title=active_settings.app_name,
        version=active_settings.app_version,
        description=(
            "Lexical URL risk assessment API with calibrated machine-learning inference "
            "and isolated rule-based fallback mode. Developed by Anil Biradar."
        ),
        lifespan=lifespan,
    )

    ml_service = MLModelService(
        artefact_path=active_settings.model_artefact_path,
        allow_fallback=active_settings.allow_fallback_mode,
    )
    app.state.settings = active_settings
    app.state.engine = app_engine
    app.state.session_factory = app_session_factory
    app.state.ml_service = ml_service
    app.state.orchestrator = URLAnalyzerOrchestrator(
        ml_service=ml_service,
        app_settings=active_settings,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=active_settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
    )

    @app.middleware("http")
    async def security_and_size_limit_middleware(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit():
            if int(content_length) > active_settings.max_request_bytes:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={
                        "error_code": "PAYLOAD_TOO_LARGE",
                        "message": f"Request body exceeds maximum permitted size of {active_settings.max_request_bytes} bytes.",
                    },
                )

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "0"
        return response

    @app.exception_handler(HTTPException)
    async def custom_http_exception_handler(_request: Request, exc: HTTPException):
        if isinstance(exc.detail, dict) and "error_code" in exc.detail:
            return JSONResponse(status_code=exc.status_code, content=exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error_code": f"HTTP_{exc.status_code}",
                "message": str(exc.detail),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(_request: Request, exc: RequestValidationError):
        errors = exc.errors()
        first_msg = "Request payload failed schema validation."
        if errors:
            loc = ".".join(str(part) for part in errors[0].get("loc", []))
            msg = errors[0].get("msg", "Invalid value")
            first_msg = f"Invalid field '{loc}': {msg}"
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error_code": "INVALID_REQUEST_PAYLOAD",
                "message": first_msg,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_request: Request, _exc: Exception):
        # Never expose internal stack traces, paths, or environment values
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error_code": "INTERNAL_ANALYSIS_ERROR",
                "message": "An unexpected error occurred while processing the request.",
            },
        )

    app.include_router(api_v1_router)
    return app


app = create_app()
