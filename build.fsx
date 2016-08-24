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

Target "BuildApp" (fun _ ->
    !! "src/**/*.csproj"
    |> MSBuildRelease buildDir "Build"
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
    ==> "BuildApp"
    ==> "Tests"
    ==> "BuildEnv"

// start build
RunTargetOrDefault "BuildEnv"
