rule rule_DllProxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DllProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DllProxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DllProxy_offensive_tool_keyword = /\.py\s.{0,1000}\.exe\s.{0,1000}NormalDLL\.dll/ nocase ascii wide
                        $string2_DllProxy_offensive_tool_keyword = /\/DllProxy\.git/ nocase ascii wide
                        $string3_DllProxy_offensive_tool_keyword = /dllproxy\.py/ nocase ascii wide
                        $string4_DllProxy_offensive_tool_keyword = "DllProxy-main" nocase ascii wide

    condition:
        any of them
}