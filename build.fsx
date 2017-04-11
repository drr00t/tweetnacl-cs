// include Fake lib
#r @"tools/FAKE/tools/FakeLib.dll"
open Fake
open Fake.Testing.NUnit3
open System

RestorePackages()

let buildDir = "./build/"
let deployDir = "./deploy/"
let testDir = "./tests/"

Target "Clean" (fun _ ->
    CleanDir buildDir
)

Target "BuildLibDebug" (fun _ ->
    !! "src/**/*.csproj"
    -- "src/**/*.Bench.csproj"
    |> MSBuildDebug buildDir "Build"
    |> Log "AppBuild-Output: "
)

Target "BuildLibRelease" (fun _ ->
    !! "src/**/*.csproj"
    -- "src/**/*.Bench.csproj"
    |> MSBuildRelease deployDir "Build"
    |> Log "AppBuild-Output: "
)

Target "Tests" (fun _ ->
    !! (buildDir + "/*.Tests.dll")
    |> NUnit3 (fun p -> 
    {p with 
        ToolPath = @"./tools/NUnit.ConsoleRunner.3.4.1/tools/nunit3-console.exe";
    })
)

// Windows
Target "BuildEnv" (fun _ ->
    trace "Running script on Windows"
)

// Dependencies Windows
"Clean"
    ==> "BuildLibDebug"
    ==> "BuildLibRelease"
    ==> "Tests"
    ==> "BuildEnv"

// start build
RunTargetOrDefault "BuildEnv"
