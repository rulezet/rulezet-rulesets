rule rule_pysoserial_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pysoserial' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysoserial"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pysoserial_offensive_tool_keyword = /\s\-c\s.{0,1000}\s\-o\spayload\.ser/ nocase ascii wide
                        $string2_pysoserial_offensive_tool_keyword = /\s\-\-command\s.{0,1000}\s\-\-output\spayload/ nocase ascii wide
                        $string3_pysoserial_offensive_tool_keyword = " -p CommonsCollections1 -c whoami" nocase ascii wide
                        $string4_pysoserial_offensive_tool_keyword = " --payload CommonsCollections" nocase ascii wide
                        $string5_pysoserial_offensive_tool_keyword = /\/Pysoserial\.git/ nocase ascii wide
                        $string6_pysoserial_offensive_tool_keyword = "generate_beanshell1" nocase ascii wide
                        $string7_pysoserial_offensive_tool_keyword = "generate_jdk8u20" nocase ascii wide
                        $string8_pysoserial_offensive_tool_keyword = "generate_mozillarhino1" nocase ascii wide
                        $string9_pysoserial_offensive_tool_keyword = "generate_mozillarhino2" nocase ascii wide
                        $string10_pysoserial_offensive_tool_keyword = /pysoserial\.py/ nocase ascii wide
                        $string11_pysoserial_offensive_tool_keyword = "Pysoserial-main" nocase ascii wide

    condition:
        any of them
}