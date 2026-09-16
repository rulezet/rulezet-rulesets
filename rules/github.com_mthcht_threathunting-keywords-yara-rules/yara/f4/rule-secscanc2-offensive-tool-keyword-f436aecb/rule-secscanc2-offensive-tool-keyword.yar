rule rule_SecScanC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SecScanC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SecScanC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SecScanC2_offensive_tool_keyword = /\/listProxyPool\?k\=/ nocase ascii wide
                        $string2_SecScanC2_offensive_tool_keyword = /\/SecScanC2\.git/ nocase ascii wide
                        $string3_SecScanC2_offensive_tool_keyword = /\/shell\?k\=.{0,1000}\&ip\=.{0,1000}\&cmd\=/ nocase ascii wide
                        $string4_SecScanC2_offensive_tool_keyword = /\/startProxyPool\?k\=.{0,1000}\&random\=n\&number\=2\&ip\=/ nocase ascii wide
                        $string5_SecScanC2_offensive_tool_keyword = /\/startProxyPool\?k\=.{0,1000}\&random\=y\&number\=2/ nocase ascii wide
                        $string6_SecScanC2_offensive_tool_keyword = "AE373FC4409EDA1B5F41D5CE3CA9290B3C7E8363" nocase ascii wide
                        $string7_SecScanC2_offensive_tool_keyword = "SecScanC2_admin " nocase ascii wide
                        $string8_SecScanC2_offensive_tool_keyword = "SecScanC2_admin_" nocase ascii wide
                        $string9_SecScanC2_offensive_tool_keyword = "SecScanC2_node " nocase ascii wide
                        $string10_SecScanC2_offensive_tool_keyword = "SecScanC2_node_" nocase ascii wide
                        $string11_SecScanC2_offensive_tool_keyword = "SecScanC2-main" nocase ascii wide
                        $string12_SecScanC2_offensive_tool_keyword = "T1esh0u/SecScanC2" nocase ascii wide

    condition:
        any of them
}