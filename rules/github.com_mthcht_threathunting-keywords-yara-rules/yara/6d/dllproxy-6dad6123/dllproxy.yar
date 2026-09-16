rule DllProxy
{
    meta:
        description = "Detection patterns for the tool 'DllProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DllProxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.py\s.{0,1000}\.exe\s.{0,1000}NormalDLL\.dll/ nocase ascii wide
                        $string2 = /\/DllProxy\.git/ nocase ascii wide
                        $string3 = /dllproxy\.py/ nocase ascii wide
                        $string4 = "DllProxy-main" nocase ascii wide

    condition:
        any of them
}