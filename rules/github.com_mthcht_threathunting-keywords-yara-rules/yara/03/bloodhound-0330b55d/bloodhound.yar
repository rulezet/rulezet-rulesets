rule BloodHound
{
    meta:
        description = "Detection patterns for the tool 'BloodHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BloodHound"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "neo4j console" nocase ascii wide

    condition:
        any of them
}