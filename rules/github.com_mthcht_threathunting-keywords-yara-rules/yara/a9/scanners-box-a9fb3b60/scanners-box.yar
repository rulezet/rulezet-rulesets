rule Scanners_Box
{
    meta:
        description = "Detection patterns for the tool 'Scanners-Box' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Scanners-Box"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Scanners-Box" nocase ascii wide

    condition:
        any of them
}