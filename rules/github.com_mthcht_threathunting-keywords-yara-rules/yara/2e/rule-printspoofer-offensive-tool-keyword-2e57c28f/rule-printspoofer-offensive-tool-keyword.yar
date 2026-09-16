rule rule_PrintSpoofer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PrintSpoofer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrintSpoofer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PrintSpoofer_offensive_tool_keyword = /\/PrintSpoofer\.exe/ nocase ascii wide
                        $string2_PrintSpoofer_offensive_tool_keyword = /\/PrintSpoofer\.git/ nocase ascii wide
                        $string3_PrintSpoofer_offensive_tool_keyword = /\\PrintSpoofer\.exe/ nocase ascii wide
                        $string4_PrintSpoofer_offensive_tool_keyword = "itm4n/PrintSpoofer" nocase ascii wide
                        $string5_PrintSpoofer_offensive_tool_keyword = /PrintSpoofer\sv\%ws\s\(by\s\@itm4n\)/ nocase ascii wide
                        $string6_PrintSpoofer_offensive_tool_keyword = /PrintSpoofer\.cpp/ nocase ascii wide
                        $string7_PrintSpoofer_offensive_tool_keyword = /PrintSpoofer\.exe/ nocase ascii wide
                        $string8_PrintSpoofer_offensive_tool_keyword = /PrintSpoofer\.sln/ nocase ascii wide
                        $string9_PrintSpoofer_offensive_tool_keyword = /PrintSpoofer32\.exe/ nocase ascii wide
                        $string10_PrintSpoofer_offensive_tool_keyword = /PrintSpoofer64\.exe/ nocase ascii wide

    condition:
        any of them
}