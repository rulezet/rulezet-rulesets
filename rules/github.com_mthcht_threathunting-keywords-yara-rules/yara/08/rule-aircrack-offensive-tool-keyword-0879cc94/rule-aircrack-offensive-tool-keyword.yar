rule rule_aircrack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'aircrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aircrack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_aircrack_offensive_tool_keyword = /\s\-r\sairolib\-db\s\/root\/wpa\.cap/ nocase ascii wide
                        $string2_aircrack_offensive_tool_keyword = "airbase-ng -" nocase ascii wide
                        $string3_aircrack_offensive_tool_keyword = /aircrack\.txt/ nocase ascii wide
                        $string4_aircrack_offensive_tool_keyword = "Aircrack-ng" nocase ascii wide
                        $string5_aircrack_offensive_tool_keyword = "aircrack-ptw-" nocase ascii wide
                        $string6_aircrack_offensive_tool_keyword = "airdecap-ng -" nocase ascii wide
                        $string7_aircrack_offensive_tool_keyword = "aireplay-ng -" nocase ascii wide
                        $string8_aircrack_offensive_tool_keyword = "airgraph-ng -" nocase ascii wide
                        $string9_aircrack_offensive_tool_keyword = "airodump-ng " nocase ascii wide
                        $string10_aircrack_offensive_tool_keyword = "airodump-ng " nocase ascii wide
                        $string11_aircrack_offensive_tool_keyword = "airolib-ng airolib-db" nocase ascii wide
                        $string12_aircrack_offensive_tool_keyword = "airserv-ng -" nocase ascii wide
                        $string13_aircrack_offensive_tool_keyword = "airtun-ng -a " nocase ascii wide
                        $string14_aircrack_offensive_tool_keyword = "besside-ng -W -v " nocase ascii wide
                        $string15_aircrack_offensive_tool_keyword = /easside\-ng\s\-.{0,1000}\s\-s\s127\.0\.0\.1/ nocase ascii wide
                        $string16_aircrack_offensive_tool_keyword = "makeivs-ng -b " nocase ascii wide
                        $string17_aircrack_offensive_tool_keyword = "wesside-ng -" nocase ascii wide

    condition:
        any of them
}