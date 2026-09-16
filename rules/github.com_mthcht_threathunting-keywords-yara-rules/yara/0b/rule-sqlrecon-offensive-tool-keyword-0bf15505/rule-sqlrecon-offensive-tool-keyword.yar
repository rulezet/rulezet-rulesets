rule rule_SQLRecon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SQLRecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SQLRecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SQLRecon_offensive_tool_keyword = /\s\-m\slagentcmd\s.{0,1000}powershell\s/ nocase ascii wide
                        $string2_SQLRecon_offensive_tool_keyword = /\s\-m\solecmd\s\-o\s.{0,1000}powershell\s/ nocase ascii wide
                        $string3_SQLRecon_offensive_tool_keyword = "/SQLRecon" nocase ascii wide
                        $string4_SQLRecon_offensive_tool_keyword = /\\SQLRecon/ nocase ascii wide
                        $string5_SQLRecon_offensive_tool_keyword = /\\temp\\hollow\.dll/ nocase ascii wide
                        $string6_SQLRecon_offensive_tool_keyword = /SQLRecon\.exe/ nocase ascii wide
                        $string7_SQLRecon_offensive_tool_keyword = /SQLRecon\.git/ nocase ascii wide

    condition:
        any of them
}