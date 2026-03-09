# STAGE 1: Build (The "Heavy" part)
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .
# Restore and Publish in one go to save space
RUN dotnet publish "SecureApp/SecureApp.csproj" -c Release -o /app/publish

# STAGE 2: Runtime (The "Lightweight" part)
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine

RUN adduser -D appuser

WORKDIR /app
COPY --from=build /app/publish .

USER appuser

ENTRYPOINT ["dotnet", "SecureApp.dll"]