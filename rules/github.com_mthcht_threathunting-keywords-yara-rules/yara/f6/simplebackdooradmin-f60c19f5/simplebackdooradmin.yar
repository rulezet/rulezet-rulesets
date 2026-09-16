rule SimpleBackdoorAdmin
{
    meta:
        description = "Detection patterns for the tool 'SimpleBackdoorAdmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimpleBackdoorAdmin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "net localgroup administrators backdoor" nocase ascii wide
                        $string2 = "net user backdoor Password123!" nocase ascii wide
                        $string3 = /SimpleBackdoorAdmin\.dll/ nocase ascii wide
                        $string4 = /SimpleBackdoorAdmin\.exe/ nocase ascii wide

    condition:
        any of them
}