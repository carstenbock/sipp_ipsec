# Stand-in PGW and HSS for regress/s8-standin-pgw (see README.md)
FROM python:3.12-slim
RUN pip install --no-cache-dir scapy
COPY standin_pgw.py /standin_pgw.py
COPY standin_hss.py /standin_hss.py
ENTRYPOINT ["python3", "/standin_pgw.py"]
