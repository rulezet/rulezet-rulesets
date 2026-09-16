rule rule_SharpKatz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpKatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpKatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpKatz_offensive_tool_keyword = /\/SharpKatz\.exe/ nocase ascii wide
                        $string2_SharpKatz_offensive_tool_keyword = /\\SharpKatz\.exe/ nocase ascii wide
                        $string3_SharpKatz_offensive_tool_keyword = /\\SharpKatz\.pdb/ nocase ascii wide
                        $string4_SharpKatz_offensive_tool_keyword = ">SharpKatz<" nocase ascii wide

    condition:
        any of them
}