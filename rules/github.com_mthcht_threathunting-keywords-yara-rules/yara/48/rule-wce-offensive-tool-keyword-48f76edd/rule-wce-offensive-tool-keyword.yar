rule rule_wce_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wce"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wce_offensive_tool_keyword = "/returnvar/wce/" nocase ascii wide
                        $string2_wce_offensive_tool_keyword = "/share/windows-resources/wce"
                        $string3_wce_offensive_tool_keyword = /\/wce32\.exe/ nocase ascii wide
                        $string4_wce_offensive_tool_keyword = /\/wce64\.exe/ nocase ascii wide
                        $string5_wce_offensive_tool_keyword = /\/wce\-beta\.zip/ nocase ascii wide
                        $string6_wce_offensive_tool_keyword = /\\wce32\.exe/ nocase ascii wide
                        $string7_wce_offensive_tool_keyword = /\\wce64\.exe/ nocase ascii wide
                        $string8_wce_offensive_tool_keyword = /\\wce\-beta\.zip/ nocase ascii wide
                        $string9_wce_offensive_tool_keyword = "apt install wce" nocase ascii wide
                        $string10_wce_offensive_tool_keyword = "wce -i 3e5 -s " nocase ascii wide
                        $string11_wce_offensive_tool_keyword = /wce.{0,1000}getlsasrvaddr\.exe/ nocase ascii wide
                        $string12_wce_offensive_tool_keyword = /wce\-master\.zip/ nocase ascii wide
                        $string13_wce_offensive_tool_keyword = /wce\-universal\.exe/ nocase ascii wide

    condition:
        any of them
}