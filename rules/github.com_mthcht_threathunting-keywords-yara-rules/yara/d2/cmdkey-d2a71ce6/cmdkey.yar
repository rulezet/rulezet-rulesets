rule Cmdkey
{
    meta:
        description = "Detection patterns for the tool 'Cmdkey' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cmdkey"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\cmdkey\.exe\\"\s\/list/ nocase ascii wide
                        $string2 = "Cmdkey /list" nocase ascii wide

    condition:
        any of them
}