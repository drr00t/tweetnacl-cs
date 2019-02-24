FROM microsoft/dotnet:2.2-sdk AS base

RUN mkdir -p /app

WORKDIR /app

COPY ./src .

RUN dotnet restore

FROM base as test

RUN dotnet test


