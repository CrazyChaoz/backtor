{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    crane.url = "github:ipetkov/crane";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
    
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      crane,
      fenix,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
      pkgs = (
        import nixpkgs {
          system = system;
          config.allowUnsupportedSystem = true;
          overlays = [ (import rust-overlay) ];
        }
      );
        

        toolchain =
          with fenix.packages.${system};
          combine [
            minimal.rustc
            minimal.cargo
            targets.x86_64-pc-windows-gnu.latest.rust-std
            targets.x86_64-unknown-linux-musl.latest.rust-std
          ];

        buildForArchitecture =
          custom_pkgs:
          ((crane.mkLib pkgs).overrideToolchain (p: p.rust-bin.stable.latest.default)).buildPackage {
            name = "arti-facts";
            src = ./.;

            strictDeps = false;
            doCheck = false;

            CARGO_BUILD_TARGET = "${custom_pkgs.stdenv.hostPlatform.rust.rustcTarget}";
            CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
            
            TARGET_CC = "${custom_pkgs.stdenv.cc}/bin/${custom_pkgs.stdenv.cc.targetPrefix}cc";

            depsBuildBuild = [
              custom_pkgs.stdenv.cc
              pkgs.perl
            ]
            ++ custom_pkgs.lib.optionals custom_pkgs.stdenv.hostPlatform.isWindows [
              custom_pkgs.windows.pthreads
            ]
            ++ custom_pkgs.lib.optionals custom_pkgs.stdenv.hostPlatform.isDarwin [
              custom_pkgs.libiconv
            ];
          };
          
          linux = buildForArchitecture pkgs.pkgsCross.musl64;
          windows = buildForArchitecture pkgs.pkgsCross.mingwW64;

      in
      {
        packages.linux = linux;
        packages.windows = windows;

        defaultPackage = pkgs.symlinkJoin {
          name = "backtor";
          paths = [
            linux
            windows
          ];
        };
      }
    );
}