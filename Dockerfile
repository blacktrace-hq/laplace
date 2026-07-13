# SEG 3 -- self-contained gate image. Build context is the gate root (laplace/),
# so oracle.py / rules / license / action all resolve. No network at runtime.
FROM python:3.12-slim
RUN pip install --no-cache-dir "cryptography>=42" "pyyaml>=6"
COPY oracle.py /laplace/oracle.py
COPY rules /laplace/rules
COPY license/verify.py /laplace/license/verify.py
COPY license/__init__.py /laplace/license/__init__.py
COPY action/entrypoint.py /laplace/action/entrypoint.py
WORKDIR /laplace
# Private key never enters the image; only license/verify.py (public key) ships.
ENTRYPOINT ["python3", "/laplace/action/entrypoint.py"]
