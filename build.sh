#!/bin/bash
SCRIPT_PATH="${BASH_SOURCE[0]}";

sudo apt-get install -y libunwind8 libssl-dev unzip mono-complete nuget libicu-dev libunwind8 gettext libssl-dev libcurl3-gnutls zlib1g sqlite3 libsqlite3-dev

nuget install FAKE "-OutputDirectory" "tools" "-ExcludeVersion" "-Version" "4.38.1"
nuget install "NUnit.Runners" "-OutputDirectory" "tools" "-Version" "3.4.1"

export encoding=utf-8
mono --runtime=v4.0 tools/FAKE/tools/FAKE.exe build.fsx "$@"
