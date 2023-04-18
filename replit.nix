{ pkgs }: {
	deps = [
		pkgs.sudo
  pkgs.bind.dnsutils
  pkgs.rustc
		pkgs.rustfmt
		pkgs.cargo
		pkgs.cargo-edit
        pkgs.rust-analyzer
	];
}