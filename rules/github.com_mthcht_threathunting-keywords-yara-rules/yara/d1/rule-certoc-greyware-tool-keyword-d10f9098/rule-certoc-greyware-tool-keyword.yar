rule rule_certoc_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'certoc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "certoc"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_certoc_greyware_tool_keyword = /certoc\.exe\s\-GetCACAPS\shttps\:\/\/raw\.githubusercontent\.com/ nocase ascii wide

    condition:
        any of them
}