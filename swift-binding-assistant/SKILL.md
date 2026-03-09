---
name: swift-binding-assistant
description: Guide users through creating .NET C# bindings for Swift or Objective-C Apple platform libraries (iOS, macOS, Mac Catalyst, tvOS). Takes a user from an SPM package URL or xcframework to a validated NuGet package using the Swift.Bindings.Sdk. Handles prerequisites, xcframework building, binding generation, error diagnosis, and optional binding review. Auto-detects whether the framework is Swift, ObjC, or mixed, and runs the correct pipeline. Triggers on "bind Swift library", "Swift to C#", "create Swift binding", "Swift NuGet package", "use Swift from .NET", "Swift interop", "Swift .NET MAUI", "bind ObjC library", "Objective-C binding", "ObjC to C#", "bind Objective-C", "ObjC NuGet", "bind iOS framework", "bind macOS framework", "bind tvOS framework", "bind Mac Catalyst framework".
---

# Swift & ObjC Binding Assistant

Guide users through creating .NET C# bindings for Swift or Objective-C Apple platform libraries using the Swift.Bindings.Sdk. Supports iOS, macOS, Mac Catalyst, and tvOS. The generator auto-detects framework type (Swift, ObjC, or mixed) and runs the correct pipeline — no flags needed.

## Documentation

The authoritative docs live in the project repository. **Always fetch the latest version** using WebFetch when you need to reference them — do NOT rely on memorized content, as it may be outdated.

| Doc | URL |
|-----|-----|
| Getting Started | `https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/Getting-Started.md` |
| Troubleshooting | `https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/Troubleshooting.md` |
| Known Limitations | `https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/Known-Limitations.md` |
| Supported Features | `https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/Supported-Features.md` |
| How Bindings Map | `https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/How-Bindings-Map.md` |
| Customization | `https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/Customization.md` |
| SwiftUI Interop | `https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/SwiftUI-Interop.md` |
| NativeAOT Deployment | `https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/NativeAOT-Deployment.md` |
| Architecture | `https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/Architecture.md` |

Fetch docs proactively when:
- The user hits a build error (fetch Troubleshooting)
- The user asks what's supported (fetch Supported Features, Known Limitations)
- The user asks how Swift types map to C# (fetch How Bindings Map)
- You need to explain a gap or skip reason (fetch Known Limitations)

## Workflow Overview

```
User Input
├── SPM package URL → Build xcframework (spm-to-xcframework)
├── GitHub release with xcframework → Download it
├── Local xcframework → Use directly
└── Vendor xcframework → Verify requirements
         │
         ▼
   Check prerequisites
         │
         ▼
   Create binding project (dotnet new swift-binding)
   Copy xcframework into project
   Configure dependencies if needed
         │
         ▼
   dotnet build
         │
    ┌────┴────┐
  Success   Errors → Diagnose (fetch Troubleshooting.md)
    │                      │
    ▼                      │
  dotnet pack    ◄─────────┘
    │
    ▼
  NuGet package ready
    │
    ▼
  Ask: "Would you like me to review the generated binding
        for completeness and usability?"

Framework type is AUTO-DETECTED during build — no flags needed:
  Swift  → Parser/Marshaler/Emitter pipeline → {Module}.cs + Swift wrapper
  ObjC   → Clang AST pipeline → ApiDefinition.cs + StructsAndEnums.cs + BgenDelegates.cs
  Mixed  → Both pipelines run → two projects emitted
```

## Step 0: Gather Information

Ask the user what they're starting with:

1. **SPM package URL** — a GitHub URL containing a `Package.swift` (e.g., `https://github.com/kean/Nuke`)
2. **Local xcframework** — a path to a `.xcframework` directory on disk
3. **A library name** — they may not know the format; help them figure out what they have

Also ask:
- What's the library name? (for the NuGet package naming)
- What platform are you targeting? (iOS is the default; also supports macOS, Mac Catalyst, tvOS)
- Is it a Swift framework, an Objective-C framework, or are you unsure? (The tool auto-detects, but knowing upfront helps set expectations for output format.)
- Does the library depend on any other frameworks? (for framework dependencies)

## Step 1: Check Prerequisites

Run these checks and report results to the user:

```bash
# macOS check (always true if we're here)
uname -s

# Xcode check
xcode-select -p
# Must show /Applications/Xcode.app/Contents/Developer or similar
# If it shows /Library/Developer/CommandLineTools, tell the user:
#   sudo xcode-select -s /Applications/Xcode.app

# .NET SDK check
dotnet --version
# Must be 10.x or later

# Platform workload check
dotnet workload list
# Must include the workload for the target platform:
#   iOS:           "ios"           → dotnet workload install ios
#   macOS:         "macos"         → dotnet workload install macos
#   Mac Catalyst:  "maccatalyst"   → dotnet workload install maccatalyst
#   tvOS:          "tvos"          → dotnet workload install tvos

# Template check
dotnet new list swift-binding
# If not found: dotnet new install Swift.Bindings.Templates
```

If any prerequisite is missing, guide the user through installing it before proceeding. Do not continue until all prerequisites pass.

## Step 2: Obtain the xcframework

### From SPM (Swift Package Manager)

If the user provides an SPM package URL:

1. Clone the spm-to-xcframework tool (if not already present):
   ```bash
   git clone https://github.com/justinwojo/spm-to-xcframework.git /tmp/spm-to-xcframework
   ```

2. Determine the latest release tag for the Swift package:
   ```bash
   git ls-remote --tags <PACKAGE_URL> | tail -5
   ```

3. Build the xcframework:
   ```bash
   /tmp/spm-to-xcframework/spm-to-xcframework <PACKAGE_URL> \
     --version <TAG> \
     --output /tmp/xcframeworks
   ```
   **Capture output to a file** — this can take several minutes:
   ```bash
   /tmp/spm-to-xcframework/spm-to-xcframework <PACKAGE_URL> \
     --version <TAG> \
     --output /tmp/xcframeworks 2>&1 | tee /tmp/spm-build.txt
   ```

4. If the library has multiple products, ask the user which one to bind (or use `--product <NAME>` to target one).

5. If the library has dependencies that the user also wants to bind, use `--include-deps`.

The tool handles `BUILD_LIBRARY_FOR_DISTRIBUTION=YES` and dynamic framework building automatically.

### From a local/vendor xcframework

Verify the xcframework meets requirements:

```bash
# Check it exists and has expected structure
ls <PATH>/Library.xcframework/

# Check it's a dynamic framework (not static)
# Look for a .framework bundle with a Mach-O binary inside
# Use the appropriate slice directory for your target platform:
#   iOS:           ios-arm64_x86_64-simulator or ios-arm64
#   macOS:         macos-arm64
#   Mac Catalyst:  ios-arm64-maccatalyst
#   tvOS:          tvos-arm64_x86_64-simulator or tvos-arm64
file <PATH>/Library.xcframework/<slice-dir>/Library.framework/Library
# Should say "dynamically linked shared library"
# If it says "current ar archive" → it's static, needs rebuild

# Check for Swift module (use appropriate slice directory)
ls <PATH>/Library.xcframework/<slice-dir>/Library.framework/Modules/*.swiftmodule 2>/dev/null
# If present → Swift framework (uses ABI JSON pipeline)
# If empty → ObjC framework (uses Clang AST pipeline) — both are fully supported

# For ObjC frameworks, verify headers exist
ls <PATH>/Library.xcframework/<slice-dir>/Library.framework/Headers/ 2>/dev/null
# ObjC frameworks need public headers for binding generation
```

**If the xcframework is static:**
- Static xcframeworks **are supported for ObjC frameworks** (e.g., Firebase/Google SDKs ship static xcframeworks and bind correctly).
- Static xcframeworks **are NOT supported for Swift frameworks** — they must be rebuilt as dynamic with `BUILD_LIBRARY_FOR_DISTRIBUTION=YES`.
- If the user controls the build, they can rebuild it. If not, suggest [spm-to-xcframework](https://github.com/justinwojo/spm-to-xcframework) if the source is available as SPM.
- If neither option works, point them to [Maui.NativeLibraryInterop](https://github.com/CommunityToolkit/Maui.NativeLibraryInterop) as an alternative approach.

## Step 3: Create the Binding Project

```bash
# Pick a working directory
mkdir -p ~/swift-bindings && cd ~/swift-bindings

# Create the project — naming convention: <LibraryName>.Swift.<Platform> or <LibraryName>.ObjC.<Platform>
# Platform suffixes: iOS, macOS, MacCatalyst, tvOS
# Use --platform to set the target (default: ios)

# iOS (default)
dotnet new swift-binding -n <LibraryName>.Swift.iOS

# macOS
dotnet new swift-binding -n <LibraryName>.Swift.macOS --platform macos

# Mac Catalyst
dotnet new swift-binding -n <LibraryName>.Swift.MacCatalyst --platform maccatalyst

# tvOS
dotnet new swift-binding -n <LibraryName>.Swift.tvOS --platform tvos

# Copy the xcframework into the project
cp -r <PATH_TO_XCFRAMEWORK> <LibraryName>.Swift.<Platform>/
```

The generated `.csproj` will look like:
```xml
<Project Sdk="Swift.Bindings.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0-ios</TargetFramework>  <!-- or net10.0-macos, net10.0-maccatalyst, net10.0-tvos -->
  </PropertyGroup>
</Project>
```

The SDK auto-detects the target platform from the TFM — no additional configuration needed beyond setting the correct TFM.

**The same `.csproj` and SDK work for both Swift and ObjC frameworks.** The SDK auto-detects the framework type during the build and runs the correct pipeline. No additional configuration is needed for ObjC frameworks.

### Framework Dependencies

If the library imports other Swift frameworks, the user needs to provide them. Add to the `.csproj`:

```xml
<ItemGroup>
  <!-- Use the platform suffix matching your target (e.g., .Swift.iOS, .Swift.macOS) -->
  <SwiftFrameworkDependency Include="../DependencyA.xcframework"
                            PackageId="DependencyA.Swift.iOS"
                            PackageVersion="1.0.0" />
</ItemGroup>
```

Each dependency also needs to be a built xcframework. If the user used `spm-to-xcframework --include-deps`, these will already exist in the output directory.

## Step 4: Build

**Always capture build output to a temp file** — it can be very long:

```bash
cd <LibraryName>.Swift.iOS
dotnet build 2>&1 | tee /tmp/swift-binding-build.txt
```

Then read the output file to check the result.

### On Success

**For Swift frameworks**, the build automatically:
- Extracts ABI metadata from the xcframework
- Runs the binding generator (produces `.cs` and `.swift` wrapper files)
- Compiles the Swift wrapper into an xcframework
- Builds the C# bindings into a DLL

**For ObjC frameworks**, the build automatically:
- Runs `clang -ast-dump=json` on the framework's umbrella header
- Parses the Clang AST into ObjC declarations
- Filters platform type stubs (types already in .NET iOS SDK)
- Generates `ApiDefinition.cs`, `StructsAndEnums.cs`, and `BgenDelegates.cs`
- Runs the .NET iOS binding tools (bgen) to compile the binding
- No Swift wrapper is needed — ObjC frameworks link directly

**For mixed frameworks** (both Swift and ObjC surface), both pipelines run and two projects are emitted.

Tell the user the build succeeded and move to Step 5.

### On Failure

**Immediately fetch the troubleshooting guide:**
```
WebFetch: https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/Troubleshooting.md
```

Then diagnose the error. Here's a quick-reference for the most common errors:

| Error | Cause | Fix |
|-------|-------|-----|
| **SWIFTBIND001** | No xcframework in project dir | Copy xcframework into the project, or add explicit `<SwiftFramework>` item |
| **SWIFTBIND002** | Multiple xcframeworks found | Add explicit `<SwiftFramework Include="...">` items |
| **SWIFTBIND050** | Swift wrapper compilation failed | Missing dependency framework — add `<SwiftFrameworkDependency>` |
| **SWIFTBIND060** | Dependency detected but not provided | Same as SWIFTBIND050 |
| **"Static xcframework detected"** | .a archive, not .dylib | Rebuild as dynamic framework |
| **"No Swift module found"** | ObjC-only framework detected | Auto-handled: ObjC pipeline runs instead. If you see this as an error, the xcframework may be malformed. |
| **"swift-frontend failed"** | Xcode version mismatch | Update Xcode, check `xcode-select -p` |
| **bgen errors (BI1xxx)** | ObjC binding tool issues | Usually type mapping — check `ApiDefinition.cs` for unsupported patterns |
| **"clang failed"** | ObjC header parsing failed | Check that Xcode CLI tools are installed and headers are accessible |
| **Generator crash / 0 types** | Missing `BUILD_LIBRARY_FOR_DISTRIBUTION=YES` | Rebuild xcframework with the flag |
| **CS0246 missing type** | Apple framework type not in .NET SDK | Members using that type can be ignored — they'll work when .NET adds the type |

After fixing, rebuild and repeat until successful.

## Step 5: Package

```bash
dotnet pack 2>&1 | tee /tmp/swift-binding-pack.txt
```

If you get **SWIFTBIND030** (missing architectures for packing), add to the `.csproj`:
```xml
<PropertyGroup>
  <SwiftWrapperArchitectures>all</SwiftWrapperArchitectures>
</PropertyGroup>
```

The output is a `.nupkg` file (e.g., `bin/Release/<tfm>/<LibraryName>.Swift.<Platform>.1.0.0.nupkg`).

Tell the user the NuGet package is ready and where to find it.

## Step 6: Offer Binding Review

After a successful build, ask the user:

> "The binding built successfully and the NuGet package is ready. Would you like me to review the generated binding for completeness and usability?"

**Only proceed with review if the user says yes.** Do not review automatically.

### If the user wants a review

#### For Swift frameworks

##### 1. Read the binding report

The binding report is the most important diagnostic. It lives at:
```
obj/Debug/<tfm>/swift-binding/binding-report.json
```

Read it and summarize:
- **Coverage**: total types vs emitted types, total members vs emitted members
- **Skip reasons**: group skipped members by reason and explain each category
- **Dependency gaps**: any `AnyTypeFallback` entries suggest missing framework dependencies

##### 2. Read the generated C# (high-level review)

The generated `.cs` file is at:
```
obj/Debug/<tfm>/swift-binding/<ModuleName>.cs
```

Scan for:
- **Overall API surface** — does it look like a reasonable representation of the library?
- **SB0001 warnings** — Mono JIT crash risk. Explain that these are safe on NativeAOT (device builds) and macOS native builds, and only affect the Mono JIT (iOS/tvOS Simulator).
- **SB0002 warnings** — missing symbols. May indicate the xcframework wasn't built with the right flags.
- **SB0003 warnings** — non-dispatchable protocol members. Normal for some protocols.
- **SB0004 warnings** — empty protocol interfaces. Check if the protocol has associated types (PAT — known limitation).
- **Naming conventions** — do method/property names follow C# conventions?

#### For ObjC frameworks

##### 1. Read the generated binding files

ObjC bindings produce three C# files in the output directory:
```
obj/Debug/<tfm>/swift-binding/ApiDefinition.cs
obj/Debug/<tfm>/swift-binding/StructsAndEnums.cs
obj/Debug/<tfm>/swift-binding/BgenDelegates.cs
```

**ApiDefinition.cs** — Review for:
- **[BaseType]** attributes with correct ObjC class names
- **[Export]** selectors matching the ObjC API
- **[Protocol, Model]** on delegate protocols (should have `WeakDelegate`/`Wrap` pattern)
- **[Abstract]** only on `@required` protocol members, not `@optional`
- **[DesignatedInitializer]** on primary constructors
- **[NullAllowed]** on nullable parameters/return types
- **Doc comments** — rich `<summary>` and `<param>` XML tags from ObjC headers
- **[Category]** extension methods on platform types (foreign-type categories)
- **Platform availability** — `[iOS(x,y)]`, `[Deprecated]`, `[Obsoleted]` attributes

**StructsAndEnums.cs** — Review for:
- **Enum naming** — C-style type prefixes should be stripped (e.g., `SDWebImageOptions` → `Options` inside the namespace)
- **Explicit enum values** — should match the ObjC header values, not be implicit sequential
- **Backing types** — `int`, `long`, `ulong` should match the ObjC typedef
- **`[Native]`** on `NSInteger`/`NSUInteger`-backed enums
- **[Field] constants** — extern constants with correct `__Internal` or library name
- **Struct layout** — structs with bitfields or anonymous unions should be skipped (with diagnostic)

**BgenDelegates.cs** — Review for:
- Block-based callback delegates (prevents bgen dedup collisions)
- These are auto-extracted and generally don't need manual attention

##### 2. Check the binding diagnostics

ObjC bindings emit diagnostic information about skipped symbols. Look for:
- **Skipped methods** — methods with unsupported parameter types (variadic methods get `[Internal]` instead of being skipped)
- **Skipped structs** — structs with unsafe layout (bitfields, anonymous unions) are skipped with a reason
- **Platform stubs filtered** — types already in the .NET Apple platform SDKs are intentionally excluded (UIButton, NSString, etc.)

#### For both Swift and ObjC

##### 3. Fetch reference docs for context

Fetch Known Limitations and Supported Features to explain any gaps:
```
WebFetch: https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/Known-Limitations.md
WebFetch: https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/Supported-Features.md
```

##### 4. Present findings

Summarize in a clear format:
- **Coverage score**: X% of types, Y% of members bound (Swift report) or count of emitted classes/protocols/enums (ObjC)
- **Notable gaps**: list significant skipped APIs with explanations
- **Warnings**: any SB-prefixed diagnostics (Swift) or bgen warnings (ObjC) and what they mean
- **Actionable items**: things the user can fix (missing dependencies, framework rebuild needed)
- **Known limitations**: things that can't be fixed today (link to the GitHub issue tracker)

## Consumer Usage

After packaging, show the user how to consume the binding:

```xml
<!-- In a .NET MAUI or Apple platform app .csproj -->
<!-- Use the package matching your target platform -->
<PackageReference Include="<LibraryName>.Swift.iOS" Version="1.0.0" />
<!-- or <LibraryName>.Swift.macOS, <LibraryName>.Swift.MacCatalyst, <LibraryName>.Swift.tvOS -->
```

```csharp
using <LibraryName>;

// Use the Swift library from C#
var result = SomeClass.DoSomething();
```

**Important consumer notes:**
- The consumer does NOT need the Swift Bindings SDK, the generator, or any Swift knowledge
- The NuGet package includes MSBuild targets that automatically bundle native frameworks
- For production device builds, NativeAOT is recommended (suppresses Mono JIT limitations):
  ```xml
  <PublishAot>true</PublishAot>
  <PublishAotUsingRuntimePack>true</PublishAotUsingRuntimePack>
  ```
  Fetch the NativeAOT guide if the user asks: `https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/NativeAOT-Deployment.md`

## Error Recovery Patterns

### "I already tried building but got errors"

If the user comes in with an existing project that has errors:
1. Ask them to share the build output or error messages
2. Fetch the Troubleshooting guide
3. Diagnose and guide them through fixes
4. Rebuild

### "The binding is missing APIs I need"

1. Read the binding report to find the skip reason
2. Fetch Known Limitations to check if it's a known gap
3. Explain the workaround (if any)
4. If it seems like a bug, suggest filing an issue at https://github.com/justinwojo/swift-dotnet-bindings/issues with the binding report attached

### "I want to customize the namespace/output"

Fetch the Customization guide:
```
WebFetch: https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/Customization.md
```

### "My ObjC binding has bgen errors"

1. Read the `ApiDefinition.cs` and the error output
2. Common bgen issues:
   - **BI1xxx type errors** — a type wasn't mapped correctly. Check if it's a typedef chain the mapper missed.
   - **Duplicate delegate definitions** — should be handled by `BgenDelegates.cs`, but may need manual dedup
   - **Missing base types** — the base class may have been filtered as a platform stub. Check if it's a .NET iOS SDK type.
3. Fetch the Troubleshooting guide for SWIFTBIND error codes
4. If the generated binding files look wrong, it may be a generator bug — suggest filing an issue

### "The ObjC binding is missing types I expected"

1. Check if the types were filtered as platform stubs (types already in the .NET Apple platform SDKs like `UIButton`, `NSString`)
2. Check if the types are from a dependency framework (need to be provided separately)
3. Types with `_`-prefixed names are suppressed by default (private API convention)
4. Structs with bitfields or anonymous unions are intentionally skipped (unsafe layout)

### "I want to use SwiftUI views from this library"

Fetch the SwiftUI Interop guide:
```
WebFetch: https://raw.githubusercontent.com/justinwojo/swift-dotnet-bindings/main/docs/SwiftUI-Interop.md
```

SwiftUI views are automatically detected and bridged — the user doesn't need to do anything extra. The bridge generates `{View}Session` classes that wrap the SwiftUI view in a `UIHostingController`.

## Project Links

- **Repository**: https://github.com/justinwojo/swift-dotnet-bindings
- **Documentation**: https://github.com/justinwojo/swift-dotnet-bindings/tree/main/docs
- **spm-to-xcframework**: https://github.com/justinwojo/spm-to-xcframework
- **File issues**: https://github.com/justinwojo/swift-dotnet-bindings/issues
