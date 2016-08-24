@echo off
cls
".nuget\NuGet.exe" "Install" "FAKE" "-OutputDirectory" "tools" "-ExcludeVersion" "-Version" "4.38.1"
".nuget\NuGet.exe" "Install" "NUnit.Runners" "-OutputDirectory" "tools" "-Version" "3.4.1"
".nuget\NuGet.exe" "Install" "NUnit" "-OutputDirectory" "src/packages" "-Version" "3.4.1"
".nuget\NuGet.exe" "Install" "Metrics.NET" "-OutputDirectory" "src/packages" "-Version" "0.3.7"
"tools\FAKE\tools\Fake.exe" build.fsx
 
pause