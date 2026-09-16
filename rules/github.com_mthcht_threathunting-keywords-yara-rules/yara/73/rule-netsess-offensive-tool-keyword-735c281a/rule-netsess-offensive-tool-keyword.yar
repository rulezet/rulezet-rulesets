rule rule_NetSess_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NetSess' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetSess"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NetSess_offensive_tool_keyword = /\/NetSess\.exe/ nocase ascii wide
                        $string2_NetSess_offensive_tool_keyword = /\/NetSess\.zip/ nocase ascii wide
                        $string3_NetSess_offensive_tool_keyword = /\\NetSess\.exe/ nocase ascii wide
                        $string4_NetSess_offensive_tool_keyword = /\\NetSess\.zip/ nocase ascii wide
                        $string5_NetSess_offensive_tool_keyword = "ddeeedc8ab9ab3b90c2e36340d4674fda3b458c0afd7514735b2857f26b14c6d" nocase ascii wide
                        $string6_NetSess_offensive_tool_keyword = "ddeeedc8ab9ab3b90c2e36340d4674fda3b458c0afd7514735b2857f26b14c6d" nocase ascii wide
                        $string7_NetSess_offensive_tool_keyword = /Get\-NetSessionEnum\.ps1/ nocase ascii wide
                        $string8_NetSess_offensive_tool_keyword = /https\:\/\/www\.joeware\.net\/downloads\/dl2\.php/ nocase ascii wide
                        $string9_NetSess_offensive_tool_keyword = /TEMP\\ns\.exe\s/ nocase ascii wide

    condition:
        any of them
}