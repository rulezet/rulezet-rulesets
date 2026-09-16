rule rule_SharpPersistSD_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpPersistSD' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpPersistSD"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpPersistSD_offensive_tool_keyword = /\sSharpPersistSD\.dll/ nocase ascii wide
                        $string2_SharpPersistSD_offensive_tool_keyword = /\/SharpPersistSD\.dll/ nocase ascii wide
                        $string3_SharpPersistSD_offensive_tool_keyword = /\/SharpPersistSD\.git/ nocase ascii wide
                        $string4_SharpPersistSD_offensive_tool_keyword = /\[\+\]\sUsing\sWMI\sto\sset\sWMI\sSD/ nocase ascii wide
                        $string5_SharpPersistSD_offensive_tool_keyword = /\\SharpPersistSD\.cs/ nocase ascii wide
                        $string6_SharpPersistSD_offensive_tool_keyword = /\\SharpPersistSD\.dll/ nocase ascii wide
                        $string7_SharpPersistSD_offensive_tool_keyword = /\\SharpPersistSD\.sln/ nocase ascii wide
                        $string8_SharpPersistSD_offensive_tool_keyword = "107EBC1B-0273-4B3D-B676-DE64B7F52B33" nocase ascii wide
                        $string9_SharpPersistSD_offensive_tool_keyword = "1db1f717560d1c53a8ec668a80aad419da22a84b1705f7dfbcc3075634634f64" nocase ascii wide
                        $string10_SharpPersistSD_offensive_tool_keyword = "cybersectroll/SharpPersistSD" nocase ascii wide
                        $string11_SharpPersistSD_offensive_tool_keyword = "e3e2ced2569d1ebef8f65b554979747881e5e060355fa6698c913036dfd892ba" nocase ascii wide
                        $string12_SharpPersistSD_offensive_tool_keyword = "f44bdc821e6588197e6d1b868a60aa140f20971a6eaeeb9e2a52bdb4065b7fd7" nocase ascii wide
                        $string13_SharpPersistSD_offensive_tool_keyword = "f93389056fa9ad53e214a468aa495adcb2ff1b75a64cd7df77a63a173066d05a" nocase ascii wide
                        $string14_SharpPersistSD_offensive_tool_keyword = "net localgroup administrators /add troll" nocase ascii wide
                        $string15_SharpPersistSD_offensive_tool_keyword = "net users /add troll Trolololol123" nocase ascii wide
                        $string16_SharpPersistSD_offensive_tool_keyword = /SharpPersistSD\.RegHelper/ nocase ascii wide
                        $string17_SharpPersistSD_offensive_tool_keyword = /SharpPersistSD\.SecurityDescriptor/ nocase ascii wide
                        $string18_SharpPersistSD_offensive_tool_keyword = /SharpPersistSD\.SvcHelper/ nocase ascii wide

    condition:
        any of them
}