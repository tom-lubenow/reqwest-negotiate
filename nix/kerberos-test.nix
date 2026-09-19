{ pkgs, client }:
let
  realm = "EXAMPLE.TEST";
  python = pkgs.python3.withPackages (ps: [ ps.gssapi ]);
  krbConfig = {
    libdefaults = {
      default_realm = realm;
      dns_lookup_kdc = false;
      dns_lookup_realm = false;
      rdns = false;
      default_ccache_name = "FILE:/tmp/krb5cc_test";
    };
    realms.${realm}.kdc = "server";
    domain_realm = { "server" = realm; };
  };
in pkgs.testers.runNixOSTest {
  name = "reqwest-negotiate-kinit";
  nodes = {
    server = { ... }: {
      security.krb5 = { enable = true; settings = krbConfig; };
      networking.firewall.allowedTCPPorts = [ 88 8080 ];
      networking.firewall.allowedUDPPorts = [ 88 ];
      environment.systemPackages = [ pkgs.krb5 ];
      environment.etc."kdc.conf".text = ''
        [kdcdefaults]
          kdc_ports = 88
          kdc_tcp_ports = 88
        [realms]
          ${realm} = {
            database_name = /var/lib/test-kdc/principal
            key_stash_file = /var/lib/test-kdc/stash
            supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
          }
      '';
      systemd.services.test-kdc = {
        wantedBy = [ "multi-user.target" ];
        environment.KRB5_KDC_PROFILE = "/etc/kdc.conf";
        path = [ pkgs.krb5 ];
        preStart = ''
          if [ ! -f /var/lib/test-kdc/principal ]; then
            kdb5_util create -s -P test-only-master-password -r ${realm}
            kadmin.local -r ${realm} -q 'addprinc -pw test-only-password alice'
            kadmin.local -r ${realm} -q 'addprinc -randkey HTTP/server'
            kadmin.local -r ${realm} -q 'ktadd -k /var/lib/test-kdc/http.keytab HTTP/server'
          fi
        '';
        serviceConfig = {
          StateDirectory = "test-kdc";
          ExecStart = "${pkgs.krb5}/bin/krb5kdc -n -r ${realm}";
        };
      };
      systemd.services.test-http = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "test-kdc.service" ];
        after = [ "test-kdc.service" ];
        environment.KRB5_KTNAME = "FILE:/var/lib/test-kdc/http.keytab";
        serviceConfig.ExecStart = "${python}/bin/python ${./gssapi-server.py}";
      };
    };
    client = { ... }: {
      security.krb5 = { enable = true; settings = krbConfig; };
      environment.systemPackages = [ client pkgs.krb5 pkgs.curl pkgs.binutils ];
    };
  };
  testScript = ''
    start_all()
    server.wait_for_unit("test-http.service")
    server.wait_for_open_port(88)
    server.wait_for_open_port(8080)
    client.wait_for_unit("multi-user.target")

    with subtest("unauthenticated requests are challenged"):
        client.succeed("curl -s -o /dev/null -w '%{http_code}' http://server:8080/ | grep 401")

    with subtest("Rust executable does not link native Kerberos"):
        client.succeed("! readelf -d ${client}/bin/negotiate | grep -Ei 'libgssapi|libkrb5'")

    with subtest("kinit TGT authenticates through a fresh TGS exchange"):
        client.succeed("printf '%s\\n' test-only-password | kinit alice")
        tickets = client.succeed("klist")
        assert "krbtgt/${realm}@${realm}" in tickets, tickets
        assert "HTTP/server" not in tickets, tickets
        result = client.succeed("negotiate http://server:8080/")
        assert "200 OK" in result, result
        assert "authenticated: alice@${realm}" in result, result

    with subtest("native curl authenticates against the same endpoint"):
        result = client.succeed("curl --fail --negotiate -u : http://server:8080/")
        assert "authenticated: alice@${realm}" in result, result

    with subtest("destroyed credentials do not authenticate"):
        client.succeed("kdestroy")
        client.fail("negotiate http://server:8080/")
  '';
}
