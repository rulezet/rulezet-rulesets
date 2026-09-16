rule SpaceRunner
{
    meta:
        description = "Detection patterns for the tool 'SpaceRunner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpaceRunner"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/spacerunner\.exe/ nocase ascii wide
                        $string2 = /\\spacerunner\.exe/ nocase ascii wide

    condition:
        any of them
}