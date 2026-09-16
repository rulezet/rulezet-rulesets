rule rule_Lockless_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Lockless' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lockless"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Lockless_offensive_tool_keyword = /\/LockLess\.exe/ nocase ascii wide
                        $string2_Lockless_offensive_tool_keyword = /\/Lockless\.git/ nocase ascii wide
                        $string3_Lockless_offensive_tool_keyword = /\\LockLess\.csproj/ nocase ascii wide
                        $string4_Lockless_offensive_tool_keyword = /\\LockLess\.exe/ nocase ascii wide
                        $string5_Lockless_offensive_tool_keyword = /\\LockLess\.sln/ nocase ascii wide
                        $string6_Lockless_offensive_tool_keyword = "8c90af89b3f0c90d39396210b6dc8dc19ff9e5ce183463a01affa6d30c5d7414" nocase ascii wide
                        $string7_Lockless_offensive_tool_keyword = "A91421CB-7909-4383-BA43-C2992BBBAC22" nocase ascii wide
                        $string8_Lockless_offensive_tool_keyword = "c591ed58f48171fa285464339a17acd1c267c0299df9f0b4e53eed9a8acb8f9f" nocase ascii wide
                        $string9_Lockless_offensive_tool_keyword = "f05885a68c1f16c7cbaa3657bbc57f54b7755910d1c96366543cc428729abcb3" nocase ascii wide
                        $string10_Lockless_offensive_tool_keyword = "GhostPack/Lockless" nocase ascii wide
                        $string11_Lockless_offensive_tool_keyword = /LockLess\.exe\s.{0,1000}\/copy/ nocase ascii wide
                        $string12_Lockless_offensive_tool_keyword = /LockLess\.exe\sall/ nocase ascii wide
                        $string13_Lockless_offensive_tool_keyword = "namespace LockLess" nocase ascii wide

    condition:
        any of them
}