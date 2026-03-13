FROM python:3.9-slim

# Устанавливаем зависимости (добавлен curl для работы с API)
RUN apt-get update && apt-get install -y wget unzip curl && rm -rf /var/lib/apt/lists/*

# Скачиваем последнюю версию nuclei динамически
RUN export LATEST_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -Po '"tag_name": "v\K[^"]*') && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${LATEST_VERSION}/nuclei_${LATEST_VERSION}_linux_amd64.zip" && \
    unzip "nuclei_${LATEST_VERSION}_linux_amd64.zip" && \
    mv nuclei /usr/bin/ && \
    rm "nuclei_${LATEST_VERSION}_linux_amd64.zip"

# Обновляем шаблоны
RUN nuclei -ut

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
