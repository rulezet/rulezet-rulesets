rule rule_usbpcap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'usbpcap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "usbpcap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_usbpcap_offensive_tool_keyword = "USBPcap" nocase ascii wide

    condition:
        any of them
}