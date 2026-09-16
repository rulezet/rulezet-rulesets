rule qaz_im
{
    meta:
        description = "Detection patterns for the tool 'qaz.im' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qaz.im"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/qaz\.im\// nocase ascii wide
                        $string2 = /https\:\/\/qaz\.im\/load\// nocase ascii wide
                        $string3 = /https\:\/\/qaz\.im\/zaq\// nocase ascii wide

    condition:
        any of them
}