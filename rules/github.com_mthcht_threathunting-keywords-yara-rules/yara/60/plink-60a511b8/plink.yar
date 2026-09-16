rule plink
{
    meta:
        description = "Detection patterns for the tool 'plink' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "plink"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /plink\s\-N\s\-L\s.{0,1000}\:localhost\:3389\s/ nocase ascii wide

    condition:
        any of them
}