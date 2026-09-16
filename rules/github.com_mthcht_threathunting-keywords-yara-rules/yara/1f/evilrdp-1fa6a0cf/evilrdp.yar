rule evilrdp
{
    meta:
        description = "Detection patterns for the tool 'evilrdp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilrdp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /dorgreen1\@gmail\.com/ nocase ascii wide
                        $string2 = /info\@skelsecprojects\.com/ nocase ascii wide

    condition:
        any of them
}