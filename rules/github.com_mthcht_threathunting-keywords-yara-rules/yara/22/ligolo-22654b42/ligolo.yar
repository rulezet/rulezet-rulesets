rule ligolo
{
    meta:
        description = "Detection patterns for the tool 'ligolo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ligolo"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-relayserver\s.{0,1000}\:5555/ nocase ascii wide
                        $string2 = /\/ligolo\.git/ nocase ascii wide
                        $string3 = "/ligolo_agent"
                        $string4 = /\/ligolo_agent\.exe/ nocase ascii wide
                        $string5 = "/ligolo-ng" nocase ascii wide
                        $string6 = "/ligolo-proxy" nocase ascii wide
                        $string7 = "/ligolo-selfcert" nocase ascii wide
                        $string8 = /\\ligolo_agent\.exe/ nocase ascii wide
                        $string9 = /\\ligolo\-proxy/ nocase ascii wide
                        $string10 = /127\.0\.0\.1\:1080/ nocase ascii wide
                        $string11 = /127\.0\.0\.1\:5555/ nocase ascii wide
                        $string12 = "bin/ligolo" nocase ascii wide
                        $string13 = "bin/localrelay" nocase ascii wide
                        $string14 = "cd ligolo" nocase ascii wide
                        $string15 = "cmd/ligolo" nocase ascii wide
                        $string16 = "cmd/localrelay" nocase ascii wide
                        $string17 = "ip link set ligolo up"
                        $string18 = /ligolo\.lan/
                        $string19 = "ligolo_darwin"
                        $string20 = "ligolo_linux"
                        $string21 = /ligolo_windows.{0,1000}\.exe/ nocase ascii wide
                        $string22 = "ligolo-master" nocase ascii wide
                        $string23 = "localrelay_linux_amd64"
                        $string24 = /proxychains\snmap\s\-sT\s.{0,1000}\s\-p\s.{0,1000}\s\-Pn\s\-A/ nocase ascii wide
                        $string25 = "proxychains rdesktop " nocase ascii wide
                        $string26 = "src/ligolo" nocase ascii wide
                        $string27 = "sysdream/ligolo" nocase ascii wide
                        $string28 = "tools/ligolo" nocase ascii wide

    condition:
        any of them
}