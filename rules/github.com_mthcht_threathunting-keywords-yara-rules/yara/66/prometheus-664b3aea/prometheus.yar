rule prometheus
{
    meta:
        description = "Detection patterns for the tool 'prometheus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "prometheus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/0xdarkvortex-" nocase ascii wide
                        $string2 = "/paranoidninja/" nocase ascii wide
                        $string3 = /\/prometheus\.exe/ nocase ascii wide
                        $string4 = "0xdarkvortex-MalwareDevelopment" nocase ascii wide

    condition:
        any of them
}