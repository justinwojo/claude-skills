---
name: swift-binding-assistant
description: Guide users through creating .NET C# bindings for Swift or Objective-C Apple platform libraries (iOS, macOS, Mac Catalyst, tvOS). Takes a user from an SPM package URL or xcframework to a validated NuGet package using the SwiftBindings.Sdk. Handles prerequisites, xcframework building, binding generation, error diagnosis, and optional binding review. Auto-detects whether the framework is Swift, ObjC, or mixed, and runs the correct pipeline. Triggers on "bind Swift library", "Swift to C#", "create Swift binding", "Swift NuGet package", "use Swift from .NET", "Swift interop", "Swift .NET MAUI", "bind ObjC library", "Objective-C binding", "ObjC to C#", "bind Objective-C", "ObjC NuGet", "bind iOS framework", "bind macOS framework", "bind tvOS framework", "bind Mac Catalyst framework", "SwiftUI from .NET", "Swift NativeAOT", "upgrade Swift bindings".
---

# Swift & ObjC Binding Assistant

Guide users through creating .NET C# bindings for Swift or Objective-C Apple platform libraries using the SwiftBindings.Sdk. Supports iOS, macOS, Mac Catalyst, and tvOS. The generator auto-detects framework type (Swift, ObjC, or mixed) and runs the correct pipeline — no flags needed.

## Documentation

The authoritative docs live in the [project wiki](https://github.com/justinwojo/swift-dotnet-bindings/wiki). **Always fetch the latest version** from the raw URLs below when you need to reference them — do NOT rely on memorized content, as it may be outdated. Use whatever fetch mechanism is available (e.g., `WebFetch`, `curl`, browser, or built-in web tools).

| Doc | URL |
|-----|-----|
| Getting Started | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/Getting-Started.md` |
| FAQ | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/FAQ.md` |
| Troubleshooting | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/Troubleshooting.md` |
| Known Limitations | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/Known-Limitations.md` |
| Supported Features | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/Supported-Features.md` |
| How Bindings Map | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/How-Bindings-Map.md` |
| Customization | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/Customization.md` |
| SwiftUI Interop | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/SwiftUI-Interop.md` |
| NativeAOT Deployment | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/NativeAOT-Deployment.md` |
| Ownership & Disposal | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/Ownership.md` |
| Upgrading | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/Upgrading.md` |
| Architecture | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/Architecture.md` |
| **Multi-Framework Libraries** | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/Multi-Framework-Libraries.md` |
| **Publishing** | `https://raw.githubusercontent.com/wiki/justinwojo/swift-dotnet-bindings/Publishing.md` |

Fetch docs proactively when:
- The user hits a build error (fetch Troubleshooting)
- The user asks what's supported (fetch Supported Features, Known Limitations)
- The user asks how Swift types map to C# (fetch How Bindings Map)
- You need to explain a gap or skip reason (fetch Known Limitations)
- The user asks about memory management or disposal (fetch Ownership)
- The user asks about upgrading versions (fetch Upgrading)
- The user is binding more than one framework from the same vendor (fetch Multi-Framework Libraries)
- The user is preparing to publish a NuGet package, sets up CI release workflows, or needs pack metadata details (fetch Publishing)
- The user has a general question (fetch FAQ first — it may already be answered)

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
# Host OS check — Apple platform binding generation requires macOS + Xcode.
# If this prints anything other than "Darwin", STOP and tell the user the
# workflow can't proceed on this host (Linux/Windows have no Xcode toolchain
# and can't compile the Swift wrapper xcframework).
uname -s

# Xcode check — requires Xcode 26 or later (not just Command Line Tools)
xcode-select -p
# Must show /Applications/Xcode.app/Contents/Developer or similar
# If it shows /Library/Developer/CommandLineTools, tell the user:
#   sudo xcode-select -s /Applications/Xcode.app

# Verify Xcode version
xcodebuild -version
# Must be Xcode 26.x or later

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
# If not found: dotnet new install SwiftBindings.Templates
```

If any prerequisite is missing, guide the user through installing it before proceeding. Do not continue until all prerequisites pass.

**Hard stop on non-macOS hosts**: if `uname -s` is not `Darwin`, the workflow cannot proceed — Apple platform bindings require Xcode, which only runs on macOS. Inform the user and stop. Do not try to suggest cross-compilation, Docker, or remote-build workarounds; there isn't a supported path today.

## Step 2: Obtain the xcframework

### From SPM (Swift Package Manager)

If the user provides an SPM package URL:

1. Clone the spm-to-xcframework tool (if not already present):
   ```bash
   git clone https://github.com/justinwojo/spm-to-xcframework.git /tmp/spm-to-xcframework
   ```

2. Determine the latest release tag for the Swift package. **Do not use `tail -5` on unsorted ls-remote output** — git returns tags in lexicographic order, so `1.10.0` would sort before `1.2.0` and you'd pick the wrong version. Use a version-aware sort instead:
   ```bash
   # Sort tags by semver descending; suffix=- pushes prereleases (-rc1, -beta) below stable releases
   git -c versionsort.suffix=- ls-remote --tags --sort=-version:refname --refs <PACKAGE_URL> \
     | head -10
   # Output: abc1234  refs/tags/12.7.3
   #         def5678  refs/tags/12.7.2
   #         ...
   # The first line after filtering prereleases is your latest stable tag.
   ```
   If the project uses non-semver tags or has unusual versioning, fall back to the GitHub releases page (`https://github.com/<owner>/<repo>/releases/latest`) or ask the user which version they want.

3. Build the xcframework (**capture output — this can take several minutes**):
   ```bash
   cd /tmp/spm-to-xcframework && swift run spm-to-xcframework \
     --url <PACKAGE_URL> \
     --version <TAG> \
     --output /tmp/xcframeworks 2>&1 | tee /tmp/spm-build.txt
   ```
   For a local Package.swift directory:
   ```bash
   cd /tmp/spm-to-xcframework && swift run spm-to-xcframework \
     --path /path/to/package \
     --output /tmp/xcframeworks 2>&1 | tee /tmp/spm-build.txt
   ```
   The output xcframework(s) will be in `/tmp/xcframeworks/`.

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

# For ObjC frameworks, verify headers and module map exist
ls <PATH>/Library.xcframework/<slice-dir>/Library.framework/Headers/ 2>/dev/null
ls <PATH>/Library.xcframework/<slice-dir>/Library.framework/Modules/module.modulemap 2>/dev/null
# ObjC frameworks need public headers AND a module.modulemap for binding generation
# The generator uses module.modulemap as the validity check for ObjC frameworks
```

**If the xcframework is static:**
- Static xcframeworks **are supported for ObjC frameworks** (e.g., Firebase/Google SDKs ship static xcframeworks and bind correctly).
- Static xcframeworks **are NOT supported for Swift frameworks** — they must be rebuilt as dynamic with `BUILD_LIBRARY_FOR_DISTRIBUTION=YES`.
- If the user controls the build, they can rebuild it. If not, suggest [spm-to-xcframework](https://github.com/justinwojo/spm-to-xcframework) if the source is available as SPM.
- If neither option works, point them to [Maui.NativeLibraryInterop](https://github.com/CommunityToolkit/Maui.NativeLibraryInterop) as an alternative approach (hand-written C wrappers, works with any xcframework).

## Step 3: Create the Binding Project

```bash
# Pick a working directory
mkdir -p ~/swift-bindings && cd ~/swift-bindings

# Create the project — naming convention:
#   Single library:        <LibraryName>.Swift.<Platform>           (e.g., Nuke.Swift.iOS)
#   Multi-vendor SDK set:  SwiftBindings.<Vendor>.<Module>          (e.g., SwiftBindings.Stripe.Core)
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
<Project Sdk="SwiftBindings.Sdk/X.Y.Z">
  <PropertyGroup>
    <TargetFramework>net10.0-ios</TargetFramework>  <!-- or net10.0-macos, net10.0-maccatalyst, net10.0-tvos -->
  </PropertyGroup>
</Project>
```

The SDK version (`X.Y.Z`) is pinned by the template at install time.

The SDK auto-detects the target platform from the TFM — no additional configuration needed beyond setting the correct TFM.

**The same `.csproj` and SDK work for both Swift and ObjC frameworks.** The SDK auto-detects the framework type during the build and runs the correct pipeline. No additional configuration is needed for ObjC frameworks.

### Framework Dependencies

If the library imports other Swift frameworks, the user needs to provide them.

**Auto-detection (default):** The SDK ships with `<SwiftAutoDetectDependencies>true</SwiftAutoDetectDependencies>` enabled by default. The build analyzes the xcframework's binary linkage, finds matching sibling binding projects in the solution, and auto-injects `<ProjectReference>` items. If a needed dependency is missing, it emits **SWIFTBIND080** with a suggested fix. In most multi-project solutions, you do not need to declare dependencies manually.

**Option 1: `<ProjectReference>` (multi-project solutions — preferred)**

For multi-product vendors (e.g., Stripe) where you're binding several frameworks in the same solution:

```xml
<ItemGroup>
  <ProjectReference Include="../DependencyA.Swift.iOS/DependencyA.Swift.iOS.csproj" />
</ItemGroup>
```

The SDK automatically resolves dependency xcframework search paths and module databases during wrapper compilation, propagates native references to the consumer's app bundle, and converts the reference into a transitive `<PackageReference>` during `dotnet pack` — no manual configuration needed.

**Option 2: `<SwiftFrameworkDependency>` (external/pre-built or internal dependencies)**

For dependencies that are pre-built xcframeworks (not sibling projects), or internal helper frameworks (e.g., ObjC-only support modules) that won't be published as their own NuGet package:

```xml
<ItemGroup>
  <!-- External, published as its own NuGet package -->
  <SwiftFrameworkDependency Include="../DependencyA.xcframework"
                            PackageId="DependencyA.Swift.iOS"
                            PackageVersion="1.0.0" />

  <!-- Internal helper, not published — omit metadata intentionally -->
  <SwiftFrameworkDependency Include="../InternalHelper.xcframework" />
</ItemGroup>
```

Each dependency also needs to be a built xcframework. If the user used `spm-to-xcframework --include-deps`, these will already exist in the output directory.

For published dependencies, both `PackageId` and `PackageVersion` are required for NuGet pack to declare the dependency (`SWIFTBIND040` warns if missing). For internal helpers that won't be published separately, the warning is intentional — consumers will need to add a `<NativeReference>` for the internal framework manually. See the **Multi-Framework Libraries** wiki page for the full pattern.

## Step 4: Build

**Always capture build output to a temp file** — it can be very long:

```bash
cd <LibraryName>.Swift.<Platform>
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
- Generates `ApiDefinition.cs` (always), plus `StructsAndEnums.cs` and `BgenDelegates.cs` if applicable
- Runs the .NET iOS binding tools (bgen) to compile the binding
- No Swift wrapper is needed — ObjC frameworks link directly

**For mixed frameworks** (both Swift and ObjC surface), both pipelines run and two projects are emitted.

Tell the user the build succeeded and move to Step 5.

### On Failure

**Immediately fetch the troubleshooting guide** from the URL in the doc table above, then diagnose the error. Here's a quick-reference for the most common errors:

| Error | Cause | Fix |
|-------|-------|-----|
| **SWIFTBIND001** | No xcframework in project dir | Copy xcframework into the project, or add explicit `<SwiftFramework>` item |
| **SWIFTBIND002** | Multiple xcframeworks found | One xcframework per project — create separate binding projects for each |
| **SWIFTBIND003** | xcframework path doesn't exist | Check the path in `<SwiftFramework>` item |
| **SWIFTBIND010** | Unsupported target framework | Use Apple platform TFM: `net10.0-ios`, `net10.0-macos`, `net10.0-maccatalyst`, `net10.0-tvos` |
| **SWIFTBIND011** | Consumer targets older platform version than library requires | Update `SupportedOSPlatformVersion` to the version shown in the warning |
| **SWIFTBIND030** | Missing architectures for packing | Set `<SwiftWrapperArchitectures>all</SwiftWrapperArchitectures>` |
| **SWIFTBIND031** | Wrapper xcframework missing device or simulator slice | Verify xcframework has both slices, or set `<IsPackable>false</IsPackable>` for local-only |
| **SWIFTBIND035** | Cannot resolve platform version for NuGet pack | Use a versioned TFM (`net10.0-ios26.0`) or install the platform workload |
| **SWIFTBIND040** | `<SwiftFrameworkDependency>` missing `PackageId`/`PackageVersion` | Add metadata if the dep is published as its own NuGet package; expected/intentional for internal-only helpers |
| **SWIFTBIND050** | Swift wrapper compilation failed | Missing dependency framework — add `<ProjectReference>` or `<SwiftFrameworkDependency>` |
| **SWIFTBIND051** | Wrapper required but failed | Fix wrapper compilation, or set `<SwiftWrapperRequired>false</SwiftWrapperRequired>` to downgrade to warning |
| **SWIFTBIND052** | SwiftUI bridge compilation failed | Bridge sessions will throw `DllNotFoundException`; main bindings unaffected |
| **SWIFTBIND060** | Dependency not provided (generator) OR skipped types count (SDK) | Context-dependent: from the generator, means a dependency xcframework is missing — provide via `<ProjectReference>` or `<SwiftFrameworkDependency>`. From the SDK build targets, reports how many types were skipped — check `binding-report.json`. |
| **SWIFTBIND080** | Cross-module dependency, no sibling project found | Add `<ProjectReference>` to the dependency binding project |
| **SWIFTBIND090-094** | Internal validation issue | Generated P/Invoke may not work at runtime — [file an issue](https://github.com/justinwojo/swift-dotnet-bindings/issues) with the xcframework |
| **SWIFTBIND100** | `<SwiftPackage>` used (not available yet) | Build xcframework from SPM first, then use `<SwiftFramework>` |
| **SWIFTBIND101** | Static xcframework detected on the Swift path | Generator auto-falls back to ObjC pipeline for ObjC static libs (Firebase, etc.) — usually transparent. Only a real failure if the static lib is genuinely Swift (must rebuild as dynamic with `MACH_O_TYPE = mh_dylib`) or if the ObjC fallback also fails (then you'll see "no ObjC module.modulemap and no Swift module") |
| **SWIFTBIND102** | No Swift module found | ObjC framework (auto-detected) or malformed xcframework |
| **SWIFTBIND103** | swift-frontend failed to extract ABI | Update Xcode, check `xcode-select -p` |
| **Generator crash / 0 types** | Missing `BUILD_LIBRARY_FOR_DISTRIBUTION=YES` | Rebuild xcframework with the flag |
| **CS0246 missing type** | Apple framework type not in .NET SDK | Members using that type can be ignored — they'll work when .NET adds the type |
| **bgen errors (BI1xxx)** | ObjC binding tool issues | Usually type mapping — check `ApiDefinition.cs` for unsupported patterns |

After fixing, rebuild and repeat until successful.

## Step 5: Package

```bash
dotnet pack 2>&1 | tee /tmp/swift-binding-pack.txt
```

The SDK defaults to `SwiftWrapperArchitectures=all`, so packing should work out of the box. If you get **SWIFTBIND030** or **SWIFTBIND031**, verify the xcframework has both device and simulator slices. If you get **SWIFTBIND035**, use a versioned TFM (`net10.0-ios26.0`) or install the platform workload.

To override the auto-extracted version (if the xcframework uses Xcode's default "1.0", you'll see warning **SWIFTBIND020**):
```xml
<PropertyGroup>
  <PackageVersion>2.5.0</PackageVersion>
</PropertyGroup>
```

The package contains everything consumers need: C# bindings DLL, source xcframework, wrapper xcframework, optional SwiftUI bridge xcframework, module database (`{Module}Database.xml`) for downstream binding projects, and a consumer `.targets` file that auto-injects `NativeReference` items.

The output is a `.nupkg` file (e.g., `bin/Release/<tfm>/<LibraryName>.Swift.<Platform>.1.0.0.nupkg`).

Tell the user the NuGet package is ready and where to find it.

**For advanced packaging needs** (CI release workflows, multi-package version coordination, local NuGet testing, publishing to nuget.org), fetch the **Publishing** wiki page from the doc table above. Highlights:
- Centralize shared metadata in `Directory.Build.props` for multi-package repos
- Pack leaf dependencies first when packaging a multi-framework set
- Tag-based GitHub Actions release pattern with dry-run support
- Local `NuGet.config` setup for iterating before publishing

## Step 6: Offer Binding Review

After a successful build, ask the user:

> "The binding built successfully and the NuGet package is ready. Would you like me to review the generated binding for completeness and usability?"

**Only proceed with review if the user says yes.** Do not review automatically.

### If the user wants a review

#### For Swift frameworks

##### 1. Read the binding report

The binding report is the most important diagnostic. It lives at:
```
obj/<config>/<tfm>/swift-binding/binding-report.json
```
Where `<config>` is `Debug` or `Release` and `<tfm>` is your target framework (e.g., `net10.0-ios`, `net10.0-macos`).

Read it and summarize:
- **Coverage**: total types vs emitted types, total members vs emitted members
- **Skip reasons**: group skipped members by reason and explain each category
- **Dependency gaps**: any `AnyTypeFallback` entries suggest missing framework dependencies

Common skip reasons:

| Skip Reason | Meaning |
|-------------|---------|
| `UnsupportedSignature` | Parameter or return type the generator can't handle yet |
| `UnsupportedType` | Type uses an unsupported Swift pattern |
| `AnyTypeFallback` | Type couldn't be resolved — check for missing dependencies |
| `UnsupportedClosure` | Closure with unsupported argument types |
| `UnsupportedExistential` | Existential type the generator can't project |
| `UnsatisfiedGenericConstraint` | Generic type argument can't satisfy C# constraints |
| `AsyncProperty` | Async computed property (not yet supported) |
| `StaticProtocolMember` | Static protocol members can't be dispatched through witness tables |
| `DuplicateSignature` | Another member already emitted with the same C# signature |
| `SwiftUIView` | SwiftUI View (handled by the bridge, not normal binding) |
| `SynthesizedCodable` | Codable `encode`/`init(from:)` pruned for cleaner API — by design |
| `UnsupportedAsyncStream` | AsyncStream/AsyncSequence can't be projected |
| `UnderscorePrefixInternal` | Underscore-prefixed type/member treated as internal |
| `ExtensionDefault` | Extension method providing a default implementation (pruned) |

##### 2. Read the generated C# (high-level review)

The generated `.cs` file is at:
```
obj/<config>/<tfm>/swift-binding/<ModuleName>.cs
```

Scan for:
- **Overall API surface** — does it look like a reasonable representation of the library?
- **SB0001 warnings** — CallConvSwift fallback. These are safe on NativeAOT (device builds) and macOS native builds. Only a risk on Mono JIT (iOS/tvOS Simulator). For representative libraries, 94-98% of P/Invokes use `CallConvCdecl` (via native ARM64 thunks or @_cdecl wrappers), so SB0001 methods are a small minority.
- **SB0002 warnings** — missing symbols. May indicate the xcframework wasn't built with the right flags.
- **SB0003 warnings** — non-dispatchable protocol members. Normal for some protocols — use concrete types instead.
- **SB0004 warnings** — empty protocol interfaces. Check if the protocol has associated types (PAT — known limitation).
- **Naming conventions** — do method/property names follow C# conventions?

#### For ObjC frameworks

##### 1. Read the generated binding files

ObjC bindings produce up to three C# files in the intermediate output directory (`obj/<config>/<tfm>/swift-binding/`). `ApiDefinition.cs` is always present; `StructsAndEnums.cs` and `BgenDelegates.cs` are conditional — only emitted if the framework has enums/structs/constants or block-based callbacks respectively. A missing file is expected, not a failure.

```
obj/<config>/<tfm>/swift-binding/ApiDefinition.cs       (always)
obj/<config>/<tfm>/swift-binding/StructsAndEnums.cs     (if enums/structs/constants exist)
obj/<config>/<tfm>/swift-binding/BgenDelegates.cs       (if block callbacks exist)
```

**ApiDefinition.cs** — Review for:
- **[BaseType]** attributes with correct ObjC class names
- **[Export]** selectors matching the ObjC API
- **[Protocol, Model]** on delegate protocols (should have `WeakDelegate`/`Wrap` pattern)
- **[Abstract]** only on `@required` protocol members, not `@optional`
- **[DesignatedInitializer]** on primary constructors
- **[DisableDefaultCtor]** on types with `NS_UNAVAILABLE` init
- **[NullAllowed]** on nullable parameters/return types
- **Doc comments** — rich `<summary>` and `<param>` XML tags from ObjC headers
- **[Category]** extension methods on platform types (foreign-type categories)
- **Platform availability** — `[Introduced(PlatformName.iOS, x, y)]`, `[Deprecated(...)]`, `[Obsoleted(...)]` attributes
- **ArgumentSemantic** — `Copy`, `Assign`, `Weak`, `Strong` on properties
- **Typed arrays** — `NSArray<NSString *>` → `string[]`
- **Pointer/out-params** — `_Bool *` → `out bool`, `CGPoint *` → `out CGPoint`

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

**ObjC Known Limitations** (MAUI bgen platform constraints, not generator bugs):
- Category protocol conformance stripped (bgen compiles `[Category]` as static classes)
- Category instance properties skipped (static extension classes can't have instance members)
- Category init methods skipped (MAUI `[Category]` can't have constructors)
- Variadic C functions skipped (`va_list` incompatible with P/Invoke)

#### For both Swift and ObjC

##### 3. Fetch reference docs for context

Fetch Known Limitations and Supported Features from the URLs in the doc table above to explain any gaps.

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
using Swift.Runtime;

// Simple usage — Swift classes work like any .NET class
var result = SomeClass.DoSomething();

// Batch operations — use SwiftDisposeScope for efficient cleanup
using (new SwiftDisposeScope())
{
    foreach (var item in items)
    {
        var processed = SomeClass.Process(item);
        // All objects disposed automatically at scope exit
    }
}
```

**Important consumer notes:**
- The consumer does NOT need the Swift Bindings SDK, the generator, or any Swift knowledge
- The NuGet package includes MSBuild targets that automatically bundle native frameworks and configure diagnostic suppression
- **Ownership**: Swift class instances have GC-safe finalizers — no explicit disposal needed for typical usage. For batch operations or struct bindings, use `SwiftDisposeScope` or `using`. The `SB1001` Roslyn analyzer surfaces undisposed locals as an **info diagnostic** (not a warning) — it's a hint for deterministic cleanup, not a correctness requirement. Fetch the Ownership guide (see doc table) if the user asks.
- **Multi-platform**: Each binding package targets a single platform (iOS, macOS, etc.). Create one binding project per platform if multiple are needed.
- For production device builds, NativeAOT is recommended:
  ```xml
  <PropertyGroup>
    <PublishAot>true</PublishAot>
    <PublishAotUsingRuntimePack>true</PublishAotUsingRuntimePack>
    <TrimMode>partial</TrimMode>
    <NoWarn>$(NoWarn);IL2026;IL2087;IL2091;IL3050</NoWarn>
  </PropertyGroup>
  ```
  Fetch the NativeAOT Deployment guide (see doc table) if the user asks.

## Binding Diagnostic IDs

| ID | Meaning | Auto-Suppressed? |
|----|---------|------------------|
| `SB0001` | **CallConvSwift fallback** — method uses direct `CallConvSwift` P/Invoke (no @_cdecl wrapper or native thunk available). May crash on Mono. Safe on NativeAOT. | Yes — in NativeAOT builds via `SwiftBindingsInteropMode` |
| `SB0002` | **Missing symbol** — P/Invoke entry point not found. Will throw `EntryPointNotFoundException`. | No |
| `SB0003` | **Non-dispatchable protocol member** — can't be called on protocol-typed values. Use a concrete type instead. | No |
| `SB0004` | **Empty protocol interface** — all members were skipped. Interface exists for type identity only. | No |
| `SB1001` | **Undisposed ISwiftObject** — Roslyn analyzer **info diagnostic** (not a warning). Suggests `using` or `Dispose()` for deterministic cleanup. GC finalizer handles correctness. | No |

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

Fetch the Customization guide from the URL in the doc table above.

Key customization options:
- **Namespace**: `<NamespacePattern>MyCompany.{Module}</NamespacePattern>` on `<SwiftFramework>` item
- **Doc comments**: Automatically extracted from Swift docs. Disable with `<SwiftGenerateDocComments>false</SwiftGenerateDocComments>`
- **Fast iteration**: `dotnet build -p:SwiftWrapperArchitectures=simulator` for simulator-only builds (~2x faster)
- **Verbose output**: `dotnet build -p:SwiftGeneratorVerbosity=2` for debug-level generator logging
- **Auto dependency detection**: Enabled by default. Disable with `<SwiftAutoDetectDependencies>false</SwiftAutoDetectDependencies>` if you need to manage `<ProjectReference>`/`<SwiftFrameworkDependency>` items manually (rare)

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

Fetch the SwiftUI Interop guide from the URL in the doc table above.

SwiftUI views are automatically detected and bridged — the user doesn't need to do anything extra. Key features:
- **Session classes**: `{View}Session` wraps the SwiftUI view in a `UIHostingController`
- **Two-way state binding**: `Update{Param}()` methods for reactive updates
- **View modifier chains**: `.AnimationSpeed(2.0)`, `.Playing()`, etc.
- **Async view factories**: `await ScannerViewSession.CreateAsync(...)` for views needing async init
- **Generic views**: Auto-resolved — `Hashable` → `String`, `Numeric` → `Int`, `View` → `EmptyView`
- **Bridge hints**: `bridge-hints.json` for skipping views, forcing templates, or adding imports

### "I want to bind multiple frameworks from the same vendor"

**Always fetch the Multi-Framework Libraries wiki page** (URL in the doc table above) when the user is binding more than one framework from the same vendor — it has the authoritative guidance and should be your primary reference.

Quick orientation:

For multi-framework SDKs (e.g., Stripe, Firebase), each xcframework gets its own binding project. Organize them in a vendor directory:

```
payments-bindings/
├── PaymentsCore/
│   ├── SwiftBindings.Payments.Core.csproj
│   └── PaymentsCore.xcframework/
├── PaymentsCrypto/                          ← internal ObjC-only helper, no csproj
│   └── PaymentsCrypto.xcframework/
├── PaymentsAuth/
│   ├── SwiftBindings.Payments.Auth.csproj   ← depends on Core + Crypto
│   └── PaymentsAuth.xcframework/
└── PaymentsUI/
    ├── SwiftBindings.Payments.UI.csproj
    └── PaymentsUI.xcframework/
```

**Auto-detection does most of the work.** The SDK ships with `<SwiftAutoDetectDependencies>true</SwiftAutoDetectDependencies>` enabled — it analyzes binary linkage, finds matching sibling binding projects, and auto-injects `<ProjectReference>` items. In most cases the user can just put projects in the same solution and build.

When you do declare dependencies explicitly:
- **`<ProjectReference>`** for sibling binding projects in the same solution. Provides cross-module type resolution, wrapper search paths, native reference propagation, and converts to a transitive `<PackageReference>` during pack — all automatic.
- **`<SwiftFrameworkDependency>`** for internal helper xcframeworks (no binding project) or external pre-built xcframeworks. Add `PackageId`/`PackageVersion` metadata if the dependency is published as its own NuGet package; omit metadata for internal-only helpers (the `SWIFTBIND040` warning is intentional in that case).

Example with both:

```xml
<!-- SwiftBindings.Payments.Auth.csproj -->
<Project Sdk="SwiftBindings.Sdk/X.Y.Z">
  <PropertyGroup>
    <TargetFramework>net10.0-ios</TargetFramework>
    <PackageId>SwiftBindings.Payments.Auth</PackageId>
    <Version>2.0.0</Version>
  </PropertyGroup>
  <ItemGroup>
    <!-- Sibling public dependency, also published as its own package -->
    <ProjectReference Include="../PaymentsCore/SwiftBindings.Payments.Core.csproj" />

    <!-- Internal ObjC-only helper, won't be published separately -->
    <SwiftFrameworkDependency Include="../PaymentsCrypto/PaymentsCrypto.xcframework" />
  </ItemGroup>
</Project>
```

**Internal vs public dependencies.** Internal frameworks (no `.swiftmodule`, ObjC-only support libraries) still need their xcframeworks at compile and runtime, but get no binding project. They're declared via `<SwiftFrameworkDependency>` without metadata. **Important:** internal frameworks are NOT bundled into the published NuGet package — consumers of the published package must add a `<NativeReference>` item in their app project to include the internal framework at runtime.

**Two-pass build pattern for CI.** A single `dotnet build` on the leaf consumer with `<ProjectReference>` items works because MSBuild orders dependencies automatically. CI systems that build each `.csproj` individually may need two passes — the first generates bindings (tolerating wrapper failures from missing dependencies), the second completes wrapper compilation:

```bash
# Pass 1: tolerate failures, generates bindings
for project in PaymentsCore PaymentsAuth PaymentsUI; do
  dotnet build $project/SwiftBindings.Payments.$project.csproj || true
done

# Pass 2: deferred wrapper compilation succeeds
for project in PaymentsCore PaymentsAuth PaymentsUI; do
  dotnet build $project/SwiftBindings.Payments.$project.csproj
done
```

**Version coordination.** Set the version once in `Directory.Build.props` or pass `/p:Version=X.Y.Z` to all `dotnet pack` calls. Pack leaf dependencies first so dependents can resolve transitive `<PackageReference>` versions. See the **Publishing** wiki page for the full release workflow pattern (tag-based GitHub Actions, dry-run support, multi-pass CI builds).

### "How do I upgrade to a new version?"

Fetch the Upgrading guide from the URL in the doc table above.

Quick steps:
1. `dotnet new install SwiftBindings.Templates` (updates template)
2. Update SDK version in `.csproj`: `<Project Sdk="SwiftBindings.Sdk/X.Y.Z">`
3. `dotnet build` (runtime version updates automatically)
4. `dotnet pack` if distributing via NuGet

### "How do I manage memory / disposal?"

Fetch the Ownership guide from the URL in the doc table above.

Quick summary:
- **Classes**: GC finalizer calls `swift_release` — no explicit disposal needed for typical use
- **Structs projected as classes**: Same — GC handles it. `using` for deterministic cleanup of scarce resources.
- **Frozen blittable structs**: Pure value types — no disposal needed at all
- **Batch operations**: `SwiftDisposeScope` for efficient cleanup of many objects
- **Protocol proxies**: Recommended to dispose (holds native witness tables)

## Project Links

- **Repository**: https://github.com/justinwojo/swift-dotnet-bindings
- **Documentation**: https://github.com/justinwojo/swift-dotnet-bindings/wiki
- **spm-to-xcframework**: https://github.com/justinwojo/spm-to-xcframework
- **File issues**: https://github.com/justinwojo/swift-dotnet-bindings/issues
