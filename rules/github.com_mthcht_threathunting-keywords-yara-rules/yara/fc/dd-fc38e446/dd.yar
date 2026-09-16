rule dd
{
    meta:
        description = "Detection patterns for the tool 'dd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dd"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "dd if=/dev/nul" nocase ascii wide
                        $string2 = "dd if=/dev/zero" nocase ascii wide
                        $string3 = /sudo\sdd\sif\=\/dev\/zero\sbs\=1000\scount\=5\sof\=.{0,1000}log/

    condition:
        any of them
}