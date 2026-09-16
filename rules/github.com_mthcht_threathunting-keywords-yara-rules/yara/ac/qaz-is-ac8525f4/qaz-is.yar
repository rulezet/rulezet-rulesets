rule qaz_is
{
    meta:
        description = "Detection patterns for the tool 'qaz.is' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qaz.is"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/qaz\.is\// nocase ascii wide
                        $string2 = /https\:\/\/qaz\.is\/load\// nocase ascii wide
                        $string3 = /https\:\/\/qaz\.is\/zaq\// nocase ascii wide

    condition:
        any of them
}