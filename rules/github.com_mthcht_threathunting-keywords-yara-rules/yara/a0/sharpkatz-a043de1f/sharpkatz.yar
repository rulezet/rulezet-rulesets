rule SharpKatz
{
    meta:
        description = "Detection patterns for the tool 'SharpKatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpKatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpKatz\.exe/ nocase ascii wide
                        $string2 = /\\SharpKatz\.exe/ nocase ascii wide
                        $string3 = /\\SharpKatz\.pdb/ nocase ascii wide
                        $string4 = ">SharpKatz<" nocase ascii wide

    condition:
        any of them
}