rule Bashfuscator
{
    meta:
        description = "Detection patterns for the tool 'Bashfuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bashfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-c\s.{0,1000}\s\-\-choose\-mutators\s.{0,1000}\s\-s\s1/
                        $string2 = "/Bashfuscator"
                        $string3 = "bashfuscator -"
                        $string4 = "Bashfuscator Team"
                        $string5 = /bashfuscator\.py/
                        $string6 = "Bashfuscator-master"
                        $string7 = /command_obfuscator\.py/

    condition:
        any of them
}