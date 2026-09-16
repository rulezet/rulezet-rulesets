rule elastic_agent
{
    meta:
        description = "Detection patterns for the tool 'elastic-agent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "elastic-agent"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /elastic\-agent\.exe\suninstall/ nocase ascii wide

    condition:
        any of them
}