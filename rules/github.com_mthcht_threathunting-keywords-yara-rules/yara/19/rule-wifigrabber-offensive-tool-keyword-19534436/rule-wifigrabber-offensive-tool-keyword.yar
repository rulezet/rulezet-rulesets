rule rule_wifigrabber_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wifigrabber' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifigrabber"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wifigrabber_offensive_tool_keyword = " > Wi-Fi-PASS" nocase ascii wide
                        $string2_wifigrabber_offensive_tool_keyword = " -InFile Wi-Fi-PASS" nocase ascii wide
                        $string3_wifigrabber_offensive_tool_keyword = "/credentials/wifigrabber" nocase ascii wide
                        $string4_wifigrabber_offensive_tool_keyword = "String netsh wlan export profile key=clear" nocase ascii wide

    condition:
        any of them
}