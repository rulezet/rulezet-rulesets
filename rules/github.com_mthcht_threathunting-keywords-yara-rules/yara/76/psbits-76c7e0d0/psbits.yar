rule PSBits
{
    meta:
        description = "Detection patterns for the tool 'PSBits' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSBits"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /EnableAllParentPrivileges\.c/ nocase ascii wide
                        $string2 = /EnableAllParentPrivileges\.exe/ nocase ascii wide

    condition:
        any of them
}