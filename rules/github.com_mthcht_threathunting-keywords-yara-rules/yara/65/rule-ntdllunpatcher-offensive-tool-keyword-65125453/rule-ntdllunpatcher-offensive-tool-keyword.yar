rule rule_NtdllUnpatcher_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NtdllUnpatcher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtdllUnpatcher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NtdllUnpatcher_offensive_tool_keyword = /\/NtdllUnpatcher\.git/ nocase ascii wide
                        $string2_NtdllUnpatcher_offensive_tool_keyword = /NtdllUnpatcher\.cpp/ nocase ascii wide
                        $string3_NtdllUnpatcher_offensive_tool_keyword = /NtdllUnpatcher\.dll/ nocase ascii wide
                        $string4_NtdllUnpatcher_offensive_tool_keyword = /NtdllUnpatcher\.lib/ nocase ascii wide
                        $string5_NtdllUnpatcher_offensive_tool_keyword = /NtdllUnpatcher\.log/ nocase ascii wide
                        $string6_NtdllUnpatcher_offensive_tool_keyword = /NtdllUnpatcher\.obj/ nocase ascii wide
                        $string7_NtdllUnpatcher_offensive_tool_keyword = /NtdllUnpatcher\.sln/ nocase ascii wide
                        $string8_NtdllUnpatcher_offensive_tool_keyword = "NtdllUnpatcher_Injector" nocase ascii wide
                        $string9_NtdllUnpatcher_offensive_tool_keyword = "NtdllUnpatcher-master" nocase ascii wide
                        $string10_NtdllUnpatcher_offensive_tool_keyword = "Signal-Labs/NtdllUnpatcher" nocase ascii wide

    condition:
        any of them
}