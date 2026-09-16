rule chashell
{
    meta:
        description = "Detection patterns for the tool 'chashell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chashell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/chashell\.git/ nocase ascii wide
                        $string2 = "release/chaserv" nocase ascii wide
                        $string3 = "release/chashell_" nocase ascii wide
                        $string4 = "sysdream/chashell" nocase ascii wide

    condition:
        any of them
}