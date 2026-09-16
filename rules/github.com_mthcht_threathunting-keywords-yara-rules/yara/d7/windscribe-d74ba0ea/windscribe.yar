rule Windscribe
{
    meta:
        description = "Detection patterns for the tool 'Windscribe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Windscribe"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "hnmpcagpplmpfojmgmnngilcnanddlhb" nocase ascii wide

    condition:
        any of them
}