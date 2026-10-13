FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp
WORKDIR /opt/qrypt
COPY pyproject.toml README.md MANIFEST.in ./
COPY requirements-container.txt ./
RUN python -m pip install --no-cache-dir --only-binary=:all: --no-deps -r requirements-container.txt
COPY src/ ./src/
RUN python -m pip install --no-cache-dir --no-deps --no-build-isolation .
RUN python -m pip check
USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["qrypt"]
