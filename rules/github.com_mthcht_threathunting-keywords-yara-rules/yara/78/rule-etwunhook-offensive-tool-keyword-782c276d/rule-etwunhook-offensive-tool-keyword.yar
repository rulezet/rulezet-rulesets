rule rule_etwunhook_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'etwunhook' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "etwunhook"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_etwunhook_offensive_tool_keyword = /\setwunhook\.cpp/ nocase ascii wide
                        $string2_etwunhook_offensive_tool_keyword = /\setwunhook\.exe/ nocase ascii wide
                        $string3_etwunhook_offensive_tool_keyword = /\/etwunhook\.cpp/ nocase ascii wide
                        $string4_etwunhook_offensive_tool_keyword = /\/etwunhook\.exe/ nocase ascii wide
                        $string5_etwunhook_offensive_tool_keyword = /\/etwunhook\.git/ nocase ascii wide
                        $string6_etwunhook_offensive_tool_keyword = /\\etwunhook\.cpp/ nocase ascii wide
                        $string7_etwunhook_offensive_tool_keyword = /\\etwunhook\.exe/ nocase ascii wide
                        $string8_etwunhook_offensive_tool_keyword = "Meowmycks/etwunhook" nocase ascii wide

    condition:
        any of them
}