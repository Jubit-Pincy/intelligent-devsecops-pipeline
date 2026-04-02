# STAGE 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy everything from the root
COPY . .

# Dynamically find the first .sln file and publish it
RUN SLN_FILE=$(ls *.sln | head -n 1) && \
    dotnet publish "$SLN_FILE" -c Release -o /app/publish

# STAGE 2: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine

RUN adduser -D appuser
WORKDIR /app

# Copy only the published output
COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:5000
USER appuser

# Dynamically find the DLL that has a runtimeconfig (the executable)
ENTRYPOINT ["sh", "-c", "dotnet $(ls *.runtimeconfig.json | sed 's/.runtimeconfig.json/.dll/')"]