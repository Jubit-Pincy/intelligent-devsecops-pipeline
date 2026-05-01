# ============================================================
# STAGE 1: Detect Language
# ============================================================
FROM alpine:3.19 AS detector

WORKDIR /scan
COPY . .

RUN apk add --no-cache bash && \
    LANG="unknown" && \
    if find . -name "*.csproj" -not -path "./risk-engine/*" | grep -q .; then \
      LANG="dotnet"; \
    elif [ -f "pom.xml" ] || find . -name "build.gradle" -not -path "./risk-engine/*" | grep -q .; then \
      LANG="java"; \
    elif [ -f "package.json" ] && [ ! -d "risk-engine" ]; then \
      LANG="node"; \
    elif find . -name "*.py" -not -path "./risk-engine/*" | grep -q .; then \
      LANG="python"; \
    elif [ -f "go.mod" ]; then \
      LANG="go"; \
    fi && \
    echo "$LANG" > /detected_lang.txt && \
    echo "Detected language: $LANG"

# ============================================================
# STAGE 2: .NET Build & Runtime
# ============================================================
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-dotnet
WORKDIR /src
COPY . .
RUN dotnet restore && \
    dotnet publish -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime-dotnet
WORKDIR /app
COPY --from=build-dotnet /app/publish .
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet"]
CMD ["app.dll"]

# ============================================================
# STAGE 3: Python Build & Runtime
# ============================================================
FROM python:3.12-slim AS runtime-python
WORKDIR /app
COPY requirements.txt* ./
RUN pip install --no-cache-dir --only-binary --require-hashes :all: -r requirements.txt 2>/dev/null || true
COPY . .
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 5000
ENV PYTHONUNBUFFERED=1
CMD ["python", "app.py"]

# ============================================================
# STAGE 4: Node.js Build & Runtime
# ============================================================
FROM node:20-slim AS runtime-node
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app
USER appuser
EXPOSE 3000
CMD ["node", "index.js"]

# ============================================================
# STAGE 5: Java Build & Runtime
# ============================================================
FROM maven:3.9-eclipse-temurin-17 AS build-java
WORKDIR /app
COPY pom.xml* ./
RUN mvn dependency:go-offline 2>/dev/null || true
COPY . .
RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jre AS runtime-java
WORKDIR /app
COPY --from=build-java /app/target/*.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]

# ============================================================
# STAGE 6: Go Build & Runtime
# ============================================================
FROM golang:1.22-alpine AS build-go
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server .

FROM alpine:3.19 AS runtime-go
WORKDIR /app
COPY --from=build-go /app/server .
RUN adduser -D appuser && chown appuser:appuser /app/server
USER appuser
EXPOSE 8080
CMD ["./server"]

# ============================================================
# FINAL: Default to detected language
# ============================================================
FROM runtime-dotnet AS final