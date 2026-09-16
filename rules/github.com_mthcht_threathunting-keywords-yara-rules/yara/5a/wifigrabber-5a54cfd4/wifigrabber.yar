rule wifigrabber
{
    meta:
        description = "Detection patterns for the tool 'wifigrabber' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifigrabber"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " > Wi-Fi-PASS" nocase ascii wide
                        $string2 = " -InFile Wi-Fi-PASS" nocase ascii wide
                        $string3 = "/credentials/wifigrabber" nocase ascii wide
                        $string4 = "String netsh wlan export profile key=clear" nocase ascii wide

    condition:
        any of them
}