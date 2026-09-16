rule qaz_su
{
    meta:
        description = "Detection patterns for the tool 'qaz.su' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qaz.su"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/qaz\.su/ nocase ascii wide
                        $string2 = /https\:\/\/qaz\.su\/load\// nocase ascii wide
                        $string3 = /https\:\/\/qaz\.su\/zaq\// nocase ascii wide

    condition:
        any of them
}