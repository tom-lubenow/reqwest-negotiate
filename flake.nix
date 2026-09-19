{
  description = "reqwest-negotiate Kerberos integration tests";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
    client = pkgs.rustPlatform.buildRustPackage {
      pname = "reqwest-negotiate-e2e";
      version = "0.1.0";
      src = pkgs.lib.cleanSource self;
      cargoLock.lockFile = ./Cargo.lock;
      buildNoDefaultFeatures = true;
      buildFeatures = [ "pure-rust" ];
      cargoBuildFlags = [ "--example" "mutual_auth" ];
      nativeBuildInputs = [ pkgs.pkg-config pkgs.cmake ];
      buildInputs = [ pkgs.openssl ];
      doCheck = false; # The VM check below runs the built client against MIT Kerberos.
      installPhase = ''
        mkdir -p $out/bin
        cp target/x86_64-unknown-linux-gnu/release/examples/mutual_auth $out/bin/negotiate
      '';
    };
  in {
    packages.${system}.default = client;
    checks.${system}.kerberos = import ./nix/kerberos-test.nix { inherit pkgs client; };
  };
}
