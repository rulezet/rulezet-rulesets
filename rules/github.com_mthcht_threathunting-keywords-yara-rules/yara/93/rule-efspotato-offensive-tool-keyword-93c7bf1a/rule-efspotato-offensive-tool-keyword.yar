rule rule_EfsPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EfsPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EfsPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EfsPotato_offensive_tool_keyword = /\/EfsPotato\.git/ nocase ascii wide
                        $string2_EfsPotato_offensive_tool_keyword = /csc\.exe\sEfsPotato\.cs\s/ nocase ascii wide
                        $string3_EfsPotato_offensive_tool_keyword = /EfsPotato.{0,1000}efsrpc/ nocase ascii wide
                        $string4_EfsPotato_offensive_tool_keyword = /EfsPotato.{0,1000}lsarpc/ nocase ascii wide
                        $string5_EfsPotato_offensive_tool_keyword = /EfsPotato.{0,1000}lsarpc/ nocase ascii wide
                        $string6_EfsPotato_offensive_tool_keyword = /EfsPotato.{0,1000}lsass/ nocase ascii wide
                        $string7_EfsPotato_offensive_tool_keyword = /EfsPotato.{0,1000}netlogon/ nocase ascii wide
                        $string8_EfsPotato_offensive_tool_keyword = /EfsPotato.{0,1000}samr/ nocase ascii wide
                        $string9_EfsPotato_offensive_tool_keyword = "EfsPotato-main" nocase ascii wide

    condition:
        any of them
}