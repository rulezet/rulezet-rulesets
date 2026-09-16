rule rule_orbitaldump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'orbitaldump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "orbitaldump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_orbitaldump_offensive_tool_keyword = /\/orbitaldump\.git/ nocase ascii wide
                        $string2_orbitaldump_offensive_tool_keyword = "k4yt3x/orbitaldump" nocase ascii wide
                        $string3_orbitaldump_offensive_tool_keyword = /orbitaldump\.py/ nocase ascii wide
                        $string4_orbitaldump_offensive_tool_keyword = "orbitaldump/orbitaldump" nocase ascii wide
                        $string5_orbitaldump_offensive_tool_keyword = "python -m orbitaldump " nocase ascii wide
                        $string6_orbitaldump_offensive_tool_keyword = "python3 -m orbitaldump " nocase ascii wide
                        $string7_orbitaldump_offensive_tool_keyword = "--user orbitaldump" nocase ascii wide

    condition:
        any of them
}