rule WINspect
{
    meta:
        description = "Detection patterns for the tool 'WINspect' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WINspect"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /WINspect\.ps1/ nocase ascii wide

    condition:
        any of them
}