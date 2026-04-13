# STAGE 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
# Define an argument so Jenkins can tell Docker which project to build
ARG PROJECT_NAME
WORKDIR /src

# Copy everything from the root
COPY . .

# FIX 1: Publish only the main project and RENAME the output to 'app'
# This removes the need for 'ls' or 'sed' later
RUN dotnet publish "${PROJECT_NAME}" -c Release -o /app/publish /p:AssemblyName=app

# STAGE 2: Runtime
# Using standard debian-slim for better compatibility with Universal tools
FROM mcr.microsoft.com/dotnet/aspnet:8.0

# Create a non-root user for security
RUN useradd -m appuser
WORKDIR /app

# Copy only the clean, published output
COPY --from=build /app/publish .

# FIX 2: .NET 8 defaults to 8080 for non-root users. 
# We'll set it explicitly to 8080 to follow modern standards.
ENV ASPNETCORE_URLS=http://+:8080
USER appuser

# FIX 3: No more 'ls' or 'sed'. The entry point is now deterministic.
ENTRYPOINT ["dotnet", "app.dll"]