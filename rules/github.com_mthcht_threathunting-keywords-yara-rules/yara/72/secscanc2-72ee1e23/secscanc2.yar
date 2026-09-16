rule SecScanC2
{
    meta:
        description = "Detection patterns for the tool 'SecScanC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SecScanC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/listProxyPool\?k\=/ nocase ascii wide
                        $string2 = /\/SecScanC2\.git/ nocase ascii wide
                        $string3 = /\/shell\?k\=.{0,1000}\&ip\=.{0,1000}\&cmd\=/ nocase ascii wide
                        $string4 = /\/startProxyPool\?k\=.{0,1000}\&random\=n\&number\=2\&ip\=/ nocase ascii wide
                        $string5 = /\/startProxyPool\?k\=.{0,1000}\&random\=y\&number\=2/ nocase ascii wide
                        $string6 = "AE373FC4409EDA1B5F41D5CE3CA9290B3C7E8363" nocase ascii wide
                        $string7 = "SecScanC2_admin " nocase ascii wide
                        $string8 = "SecScanC2_admin_" nocase ascii wide
                        $string9 = "SecScanC2_node " nocase ascii wide
                        $string10 = "SecScanC2_node_" nocase ascii wide
                        $string11 = "SecScanC2-main" nocase ascii wide
                        $string12 = "T1esh0u/SecScanC2" nocase ascii wide

    condition:
        any of them
}