﻿FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
USER $APP_UID
WORKDIR /app

ENV ASPNETCORE_URLS=https://+:8081
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["FFXIVVenues.Identity/FFXIVVenues.Identity.csproj", "FFXIVVenues.Identity/"]
RUN dotnet restore "FFXIVVenues.Identity/FFXIVVenues.Identity.csproj"
COPY . .
WORKDIR "/src/FFXIVVenues.Identity"
RUN dotnet build "FFXIVVenues.Identity.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "FFXIVVenues.Identity.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "FFXIVVenues.Identity.dll"]
