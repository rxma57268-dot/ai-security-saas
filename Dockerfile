FROM python:3.12-slim

WORKDIR /srv/app

# 先装依赖再拷代码：依赖层可被 Docker 缓存复用
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY dataset ./dataset

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

# 生产建议：--workers 按 CPU 核数调；探测是后台任务，单实例多 worker
# 会导致后台任务归属随机（MVP 接受，见 README 已知局限）
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
