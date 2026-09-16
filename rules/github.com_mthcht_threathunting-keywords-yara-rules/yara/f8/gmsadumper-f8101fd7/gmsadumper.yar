rule gMSADumper
{
    meta:
        description = "Detection patterns for the tool 'gMSADumper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gMSADumper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/gMSADumper" nocase ascii wide
                        $string2 = /gMSADumper\.py/ nocase ascii wide
                        $string3 = "micahvandeusen/gMSADumper" nocase ascii wide

    condition:
        any of them
}