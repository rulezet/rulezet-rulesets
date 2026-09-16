rule orbitaldump
{
    meta:
        description = "Detection patterns for the tool 'orbitaldump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "orbitaldump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/orbitaldump\.git/ nocase ascii wide
                        $string2 = "k4yt3x/orbitaldump" nocase ascii wide
                        $string3 = /orbitaldump\.py/ nocase ascii wide
                        $string4 = "orbitaldump/orbitaldump" nocase ascii wide
                        $string5 = "python -m orbitaldump " nocase ascii wide
                        $string6 = "python3 -m orbitaldump " nocase ascii wide
                        $string7 = "--user orbitaldump" nocase ascii wide

    condition:
        any of them
}