rule pysoserial
{
    meta:
        description = "Detection patterns for the tool 'pysoserial' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysoserial"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-c\s.{0,1000}\s\-o\spayload\.ser/ nocase ascii wide
                        $string2 = /\s\-\-command\s.{0,1000}\s\-\-output\spayload/ nocase ascii wide
                        $string3 = " -p CommonsCollections1 -c whoami" nocase ascii wide
                        $string4 = " --payload CommonsCollections" nocase ascii wide
                        $string5 = /\/Pysoserial\.git/ nocase ascii wide
                        $string6 = "generate_beanshell1" nocase ascii wide
                        $string7 = "generate_jdk8u20" nocase ascii wide
                        $string8 = "generate_mozillarhino1" nocase ascii wide
                        $string9 = "generate_mozillarhino2" nocase ascii wide
                        $string10 = /pysoserial\.py/ nocase ascii wide
                        $string11 = "Pysoserial-main" nocase ascii wide

    condition:
        any of them
}