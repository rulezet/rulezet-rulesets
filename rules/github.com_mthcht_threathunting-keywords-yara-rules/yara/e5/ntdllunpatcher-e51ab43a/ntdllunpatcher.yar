rule NtdllUnpatcher
{
    meta:
        description = "Detection patterns for the tool 'NtdllUnpatcher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtdllUnpatcher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/NtdllUnpatcher\.git/ nocase ascii wide
                        $string2 = /NtdllUnpatcher\.cpp/ nocase ascii wide
                        $string3 = /NtdllUnpatcher\.dll/ nocase ascii wide
                        $string4 = /NtdllUnpatcher\.lib/ nocase ascii wide
                        $string5 = /NtdllUnpatcher\.log/ nocase ascii wide
                        $string6 = /NtdllUnpatcher\.obj/ nocase ascii wide
                        $string7 = /NtdllUnpatcher\.sln/ nocase ascii wide
                        $string8 = "NtdllUnpatcher_Injector" nocase ascii wide
                        $string9 = "NtdllUnpatcher-master" nocase ascii wide
                        $string10 = "Signal-Labs/NtdllUnpatcher" nocase ascii wide

    condition:
        any of them
}