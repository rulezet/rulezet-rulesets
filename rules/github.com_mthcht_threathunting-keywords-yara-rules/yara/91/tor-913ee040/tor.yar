rule tor
{
    meta:
        description = "Detection patterns for the tool 'tor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/bin/torify"
                        $string2 = /\/dpkg\/info\/tor\.list/
                        $string3 = /\/etc\/cron\.weekly\/tor/
                        $string4 = "/etc/default/tor"
                        $string5 = /\/etc\/init\.d\/tor/
                        $string6 = "/etc/sv/tor/log"
                        $string7 = /\/etc\/tor\/.{0,1000}\.conf/
                        $string8 = /\/invocation\:tor\.service/
                        $string9 = /\/multi\-user\.target\.wants\/tor\.service/
                        $string10 = /\/proxy\/Tor\.py/
                        $string11 = /\/proxy\/tor_paths\.py/
                        $string12 = "/run/tor/socks"
                        $string13 = /\/run\/tor\/tor\.pid/
                        $string14 = "/tor -mindepth 1 -maxdepth 1 -type f "
                        $string15 = "/tor/torrc"
                        $string16 = "/tor-archive-keyring"
                        $string17 = /\/tor\-gencert\.exe/
                        $string18 = /\/tor\-geoipdb\.list/
                        $string19 = /\/torsocks\.conf/
                        $string20 = /\/torsocks\.list/
                        $string21 = "/usr/sbin/tor"
                        $string22 = "/var/lib/tor/"
                        $string23 = "/var/log/tor/"
                        $string24 = /\/win\/Tor\/tor\.exe/ nocase ascii wide
                        $string25 = /127\.0\.0\.1\:9050/
                        $string26 = "apt install tor "
                        $string27 = /deb\.torproject\.org\/torproject\.org\//
                        $string28 = /deb\.torproject\.org\-keyring/
                        $string29 = "debian-tor:x"
                        $string30 = /r0oth3x49\/Tor\.git/
                        $string31 = /tor\@default\.service/
                        $string32 = /tor_services\.py/
                        $string33 = "tor2socks"
                        $string34 = "tor-geoipdb:all"
                        $string35 = "tor-geoipdb:amd64"
                        $string36 = "torify curl "
                        $string37 = "torify ghaur "
                        $string38 = "torify nuclei "
                        $string39 = "torify sqlmap "
                        $string40 = "TorServiceSetup"
                        $string41 = "torsocks:amd64"

    condition:
        any of them
}