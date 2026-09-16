rule DBC2
{
    meta:
        description = "Detection patterns for the tool 'DBC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DBC2"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/api\.dropboxapi\.com\// nocase ascii wide

    condition:
        any of them
}