rule rule_regsvr32_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'regsvr32' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "regsvr32"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_regsvr32_greyware_tool_keyword = /cmd\s\/c\sregsvr32\.exe\s\/s\sC\:\\.{0,1000}\\desktop\.ini\\"\sstart\=\sauto/ nocase ascii wide
                        $string2_regsvr32_greyware_tool_keyword = /regsvr32\sAmsiProvider\.dll/ nocase ascii wide
                        $string3_regsvr32_greyware_tool_keyword = /sc\screate\s.{0,1000}cmd\s\/c\sregsvr32\.exe\s\/s\s.{0,1000}\\desktop\.ini/ nocase ascii wide

    condition:
        any of them
}