rule rule_wireshark_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wireshark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wireshark"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_wireshark_greyware_tool_keyword = "bin/wireshark" nocase ascii wide
                        $string2_wireshark_greyware_tool_keyword = /dl\.wireshark\.org/ nocase ascii wide
                        $string3_wireshark_greyware_tool_keyword = "dumpcap -" nocase ascii wide
                        $string4_wireshark_greyware_tool_keyword = "install tshark" nocase ascii wide
                        $string5_wireshark_greyware_tool_keyword = "libwireshark16" nocase ascii wide
                        $string6_wireshark_greyware_tool_keyword = "libwireshark-data" nocase ascii wide
                        $string7_wireshark_greyware_tool_keyword = "libwireshark-dev" nocase ascii wide
                        $string8_wireshark_greyware_tool_keyword = "libwiretap13" nocase ascii wide
                        $string9_wireshark_greyware_tool_keyword = "--no-promiscuous-mode" nocase ascii wide
                        $string10_wireshark_greyware_tool_keyword = "sharkd -a tcp:" nocase ascii wide
                        $string11_wireshark_greyware_tool_keyword = /tshark\s.{0,1000}\-i\s/ nocase ascii wide
                        $string12_wireshark_greyware_tool_keyword = "tshark -f " nocase ascii wide
                        $string13_wireshark_greyware_tool_keyword = "tshark -Q" nocase ascii wide
                        $string14_wireshark_greyware_tool_keyword = "tshark -r " nocase ascii wide
                        $string15_wireshark_greyware_tool_keyword = /tshark.{0,1000}\.deb/ nocase ascii wide
                        $string16_wireshark_greyware_tool_keyword = "Wireshark" nocase ascii wide
                        $string17_wireshark_greyware_tool_keyword = /wireshark.{0,1000}\.deb/ nocase ascii wide
                        $string18_wireshark_greyware_tool_keyword = /Wireshark.{0,1000}\.dmg/ nocase ascii wide
                        $string19_wireshark_greyware_tool_keyword = /wireshark\-.{0,1000}\.tar\.xz/ nocase ascii wide
                        $string20_wireshark_greyware_tool_keyword = "wireshark-common" nocase ascii wide
                        $string21_wireshark_greyware_tool_keyword = "wireshark-dev" nocase ascii wide
                        $string22_wireshark_greyware_tool_keyword = "wireshark-gtk" nocase ascii wide
                        $string23_wireshark_greyware_tool_keyword = "WiresharkPortable64" nocase ascii wide
                        $string24_wireshark_greyware_tool_keyword = "wireshark-qt" nocase ascii wide
                        $string25_wireshark_greyware_tool_keyword = /Wireshark\-win.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}