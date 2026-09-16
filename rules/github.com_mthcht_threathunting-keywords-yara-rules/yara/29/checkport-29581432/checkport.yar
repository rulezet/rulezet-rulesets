rule CheckPort
{
    meta:
        description = "Detection patterns for the tool 'CheckPort' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CheckPort"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/CheckPort\.exe/ nocase ascii wide
                        $string2 = /\\CheckPort\.exe/ nocase ascii wide
                        $string3 = /\\Release\\CheckPort\.pdb/ nocase ascii wide
                        $string4 = "'Product'>CheckPort" nocase ascii wide

    condition:
        any of them
}