rule tempsend_com
{
    meta:
        description = "Detection patterns for the tool 'tempsend.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tempsend.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/tempsend\.com\// nocase ascii wide
                        $string2 = /https\:\/\/tempsend\.com\/send/ nocase ascii wide

    condition:
        any of them
}