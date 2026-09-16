rule vncpwdump
{
    meta:
        description = "Detection patterns for the tool 'vncpwdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vncpwdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\vncdump\-/ nocase ascii wide
                        $string2 = "vncdumpdll" nocase ascii wide
                        $string3 = /vncpwdump\./ nocase ascii wide

    condition:
        any of them
}