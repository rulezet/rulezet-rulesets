rule EAPHammer
{
    meta:
        description = "Detection patterns for the tool 'EAPHammer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EAPHammer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "eaphammer" nocase ascii wide

    condition:
        any of them
}