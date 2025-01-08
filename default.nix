{ pkgs }:

pkgs.rustPlatform.buildRustPackage {
  pname = "circom-compat-ffi";
  version = "0.1.0";

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
    allowBuiltinFetchGit = true;
  };

  CARGO_HOME = "/tmp";

  meta = with pkgs.lib; {
    description = "circom-compat (ark-circom) ffi";
    license = licenses.mit;
  };
}