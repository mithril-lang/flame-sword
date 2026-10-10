FROM python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce AS dependencies
# Trusted dependency preparation only. No generated source or credentials enter this image.
RUN python -m pip install --no-cache-dir Flask==2.3.2 Werkzeug==2.3.8 \
    Jinja2==3.1.6 MarkupSafe==3.0.3 itsdangerous==2.2.0 click==8.1.8 blinker==1.9.0

# Retain the prepared filesystem without inheriting build-time image metadata.
FROM scratch
COPY --from=dependencies / /
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8
