rule rule_Bashfuscator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Bashfuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bashfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Bashfuscator_offensive_tool_keyword = /\s\-c\s.{0,1000}\s\-\-choose\-mutators\s.{0,1000}\s\-s\s1/
                        $string2_Bashfuscator_offensive_tool_keyword = "/Bashfuscator"
                        $string3_Bashfuscator_offensive_tool_keyword = "bashfuscator -"
                        $string4_Bashfuscator_offensive_tool_keyword = "Bashfuscator Team"
                        $string5_Bashfuscator_offensive_tool_keyword = /bashfuscator\.py/
                        $string6_Bashfuscator_offensive_tool_keyword = "Bashfuscator-master"
                        $string7_Bashfuscator_offensive_tool_keyword = /command_obfuscator\.py/

    condition:
        any of them
}