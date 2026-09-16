rule SharpUnhooker
{
    meta:
        description = "Detection patterns for the tool 'SharpUnhooker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpUnhooker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpUnhooker\.git/ nocase ascii wide
                        $string2 = "GetRektBoy724/SharpUnhooker" nocase ascii wide
                        $string3 = /SharpUnhooker\./ nocase ascii wide
                        $string4 = "SharpUnhooker-main" nocase ascii wide

    condition:
        any of them
}