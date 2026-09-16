rule rule_SharpZeroLogon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpZeroLogon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpZeroLogon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpZeroLogon_offensive_tool_keyword = /\/SharpZeroLogon\.git/ nocase ascii wide
                        $string2_SharpZeroLogon_offensive_tool_keyword = /\\SharpZeroLogon\.sln/ nocase ascii wide
                        $string3_SharpZeroLogon_offensive_tool_keyword = ">SharpZeroLogon<" nocase ascii wide
                        $string4_SharpZeroLogon_offensive_tool_keyword = "0bef49d95cf04914b2824fe3957dc3b9f66447c150877254ddbbf36dd7b231b8" nocase ascii wide
                        $string5_SharpZeroLogon_offensive_tool_keyword = "15ce9a3c-4609-4184-87b2-e29fc5e2b770" nocase ascii wide
                        $string6_SharpZeroLogon_offensive_tool_keyword = "465a8ba788d324313ccf9d344f35ce5d1d4153d0367c6f647bfa817be18934ce" nocase ascii wide
                        $string7_SharpZeroLogon_offensive_tool_keyword = "leitosama/SharpZeroLogon" nocase ascii wide
                        $string8_SharpZeroLogon_offensive_tool_keyword = /SharpZeroLogon\.exe/ nocase ascii wide
                        $string9_SharpZeroLogon_offensive_tool_keyword = "Success! DC can be fully compromised by a Zerologon attack" nocase ascii wide

    condition:
        any of them
}