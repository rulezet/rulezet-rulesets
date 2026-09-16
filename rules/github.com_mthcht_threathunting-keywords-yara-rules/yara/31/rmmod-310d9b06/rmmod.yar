rule rmmod
{
    meta:
        description = "Detection patterns for the tool 'rmmod' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rmmod"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "rmmod -r" nocase ascii wide
                        $string2 = "rmmod --remove" nocase ascii wide
                        $string3 = "sudo rmmod -r"

    condition:
        any of them
}