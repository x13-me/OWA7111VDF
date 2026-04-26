{
  description = "ttyd WebSocket terminal client for OWA7111";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs =
    { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python3.withPackages (ps: [
            ps.websockets
          ]);
        in
        {
          # Interactive client - connects stdin/stdout to the remote shell
          client = pkgs.writeShellApplication {
            name = "ttyd-client";
            runtimeInputs = [ python ];
            text = ''
              python3 ${./ttyd_client.py} "''${1:-ws://10.0.2.174:7689/ws}"
            '';
          };

          # Fuzzer
          fuzz = pkgs.writeShellApplication {
            name = "ttyd-fuzz";
            runtimeInputs = [ python ];
            text = ''
              python3 ${./ttyd_fuzz.py} "''${1:-ws://10.0.2.174:7689/ws}"
            '';
          };

          default = self.packages.${system}.client;
        }
      );

      apps = forAllSystems (system: {
        test = {
          type = "app";
          program = "${self.packages.${system}.test}/bin/ttyd-test";
        };
        client = {
          type = "app";
          program = "${self.packages.${system}.client}/bin/ttyd-client";
        };
        default = self.apps.${system}.client;
      });
    };
}
