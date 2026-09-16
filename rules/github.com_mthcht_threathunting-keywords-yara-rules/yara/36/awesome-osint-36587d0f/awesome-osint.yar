rule awesome_osint
{
    meta:
        description = "Detection patterns for the tool 'awesome-osint' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awesome-osint"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "awesome-osint" nocase ascii wide

    condition:
        any of them
}