rule wireshark
{
    meta:
        description = "Detection patterns for the tool 'wireshark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wireshark"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "bin/wireshark" nocase ascii wide
                        $string2 = /dl\.wireshark\.org/ nocase ascii wide
                        $string3 = "dumpcap -" nocase ascii wide
                        $string4 = "install tshark" nocase ascii wide
                        $string5 = "libwireshark16" nocase ascii wide
                        $string6 = "libwireshark-data" nocase ascii wide
                        $string7 = "libwireshark-dev" nocase ascii wide
                        $string8 = "libwiretap13" nocase ascii wide
                        $string9 = "--no-promiscuous-mode" nocase ascii wide
                        $string10 = "sharkd -a tcp:" nocase ascii wide
                        $string11 = /tshark\s.{0,1000}\-i\s/ nocase ascii wide
                        $string12 = "tshark -f " nocase ascii wide
                        $string13 = "tshark -Q" nocase ascii wide
                        $string14 = "tshark -r " nocase ascii wide
                        $string15 = /tshark.{0,1000}\.deb/ nocase ascii wide
                        $string16 = "Wireshark" nocase ascii wide
                        $string17 = /wireshark.{0,1000}\.deb/ nocase ascii wide
                        $string18 = /Wireshark.{0,1000}\.dmg/ nocase ascii wide
                        $string19 = /wireshark\-.{0,1000}\.tar\.xz/ nocase ascii wide
                        $string20 = "wireshark-common" nocase ascii wide
                        $string21 = "wireshark-dev" nocase ascii wide
                        $string22 = "wireshark-gtk" nocase ascii wide
                        $string23 = "WiresharkPortable64" nocase ascii wide
                        $string24 = "wireshark-qt" nocase ascii wide
                        $string25 = /Wireshark\-win.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}