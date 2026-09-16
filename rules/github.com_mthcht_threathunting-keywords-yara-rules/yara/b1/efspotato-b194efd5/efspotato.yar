rule EfsPotato
{
    meta:
        description = "Detection patterns for the tool 'EfsPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EfsPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/EfsPotato\.git/ nocase ascii wide
                        $string2 = /csc\.exe\sEfsPotato\.cs\s/ nocase ascii wide
                        $string3 = /EfsPotato.{0,1000}efsrpc/ nocase ascii wide
                        $string4 = /EfsPotato.{0,1000}lsarpc/ nocase ascii wide
                        $string5 = /EfsPotato.{0,1000}lsarpc/ nocase ascii wide
                        $string6 = /EfsPotato.{0,1000}lsass/ nocase ascii wide
                        $string7 = /EfsPotato.{0,1000}netlogon/ nocase ascii wide
                        $string8 = /EfsPotato.{0,1000}samr/ nocase ascii wide
                        $string9 = "EfsPotato-main" nocase ascii wide

    condition:
        any of them
}