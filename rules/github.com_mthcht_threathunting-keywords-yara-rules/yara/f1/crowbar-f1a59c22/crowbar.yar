rule Crowbar
{
    meta:
        description = "Detection patterns for the tool 'Crowbar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Crowbar"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "crowbar" nocase ascii wide

    condition:
        any of them
}