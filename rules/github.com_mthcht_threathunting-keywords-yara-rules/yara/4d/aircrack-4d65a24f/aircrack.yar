rule aircrack
{
    meta:
        description = "Detection patterns for the tool 'aircrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aircrack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-r\sairolib\-db\s\/root\/wpa\.cap/ nocase ascii wide
                        $string2 = "airbase-ng -" nocase ascii wide
                        $string3 = /aircrack\.txt/ nocase ascii wide
                        $string4 = "Aircrack-ng" nocase ascii wide
                        $string5 = "aircrack-ptw-" nocase ascii wide
                        $string6 = "airdecap-ng -" nocase ascii wide
                        $string7 = "aireplay-ng -" nocase ascii wide
                        $string8 = "airgraph-ng -" nocase ascii wide
                        $string9 = "airodump-ng " nocase ascii wide
                        $string10 = "airodump-ng " nocase ascii wide
                        $string11 = "airolib-ng airolib-db" nocase ascii wide
                        $string12 = "airserv-ng -" nocase ascii wide
                        $string13 = "airtun-ng -a " nocase ascii wide
                        $string14 = "besside-ng -W -v " nocase ascii wide
                        $string15 = /easside\-ng\s\-.{0,1000}\s\-s\s127\.0\.0\.1/ nocase ascii wide
                        $string16 = "makeivs-ng -b " nocase ascii wide
                        $string17 = "wesside-ng -" nocase ascii wide

    condition:
        any of them
}