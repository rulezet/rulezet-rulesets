rule modproble
{
    meta:
        description = "Detection patterns for the tool 'modproble' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "modproble"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "modprobe -r" nocase ascii wide
                        $string2 = "modprobe --remove" nocase ascii wide
                        $string3 = "modprobe rmmod -r" nocase ascii wide

    condition:
        any of them
}