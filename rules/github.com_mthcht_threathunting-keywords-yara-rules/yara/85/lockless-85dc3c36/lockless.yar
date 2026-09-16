rule Lockless
{
    meta:
        description = "Detection patterns for the tool 'Lockless' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lockless"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/LockLess\.exe/ nocase ascii wide
                        $string2 = /\/Lockless\.git/ nocase ascii wide
                        $string3 = /\\LockLess\.csproj/ nocase ascii wide
                        $string4 = /\\LockLess\.exe/ nocase ascii wide
                        $string5 = /\\LockLess\.sln/ nocase ascii wide
                        $string6 = "8c90af89b3f0c90d39396210b6dc8dc19ff9e5ce183463a01affa6d30c5d7414" nocase ascii wide
                        $string7 = "A91421CB-7909-4383-BA43-C2992BBBAC22" nocase ascii wide
                        $string8 = "c591ed58f48171fa285464339a17acd1c267c0299df9f0b4e53eed9a8acb8f9f" nocase ascii wide
                        $string9 = "f05885a68c1f16c7cbaa3657bbc57f54b7755910d1c96366543cc428729abcb3" nocase ascii wide
                        $string10 = "GhostPack/Lockless" nocase ascii wide
                        $string11 = /LockLess\.exe\s.{0,1000}\/copy/ nocase ascii wide
                        $string12 = /LockLess\.exe\sall/ nocase ascii wide
                        $string13 = "namespace LockLess" nocase ascii wide

    condition:
        any of them
}