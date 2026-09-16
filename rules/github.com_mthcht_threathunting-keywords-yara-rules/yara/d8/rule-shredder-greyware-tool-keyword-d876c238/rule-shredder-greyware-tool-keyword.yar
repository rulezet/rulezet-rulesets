rule rule_Shredder_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Shredder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shredder"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Shredder_greyware_tool_keyword = /\\file_shredder_setup\.tmp/ nocase ascii wide
                        $string2_Shredder_greyware_tool_keyword = /\\Shredder\.exe/ nocase ascii wide
                        $string3_Shredder_greyware_tool_keyword = ">File Shredder by PowTools<" nocase ascii wide
                        $string4_Shredder_greyware_tool_keyword = /File\sShredder\ssetup\.exe/ nocase ascii wide
                        $string5_Shredder_greyware_tool_keyword = /File\sShredder\.exe/ nocase ascii wide
                        $string6_Shredder_greyware_tool_keyword = /file_shredder_setup\.exe/ nocase ascii wide
                        $string7_Shredder_greyware_tool_keyword = /Program\sFiles\\File\sShredder\\/ nocase ascii wide

    condition:
        any of them
}