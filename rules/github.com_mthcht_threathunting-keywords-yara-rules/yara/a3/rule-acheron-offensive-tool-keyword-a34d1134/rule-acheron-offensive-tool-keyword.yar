rule rule_acheron_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'acheron' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "acheron"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_acheron_offensive_tool_keyword = /\/acheron\.git/ nocase ascii wide
                        $string2_acheron_offensive_tool_keyword = /\/acheron\.go/ nocase ascii wide
                        $string3_acheron_offensive_tool_keyword = /\/direct_syscall_amd64\.s/ nocase ascii wide
                        $string4_acheron_offensive_tool_keyword = "/sc_inject/inject/" nocase ascii wide
                        $string5_acheron_offensive_tool_keyword = /acheron\-master\.zip/ nocase ascii wide
                        $string6_acheron_offensive_tool_keyword = "f1zm0/acheron" nocase ascii wide
                        $string7_acheron_offensive_tool_keyword = /process_snapshot\.exe/ nocase ascii wide
                        $string8_acheron_offensive_tool_keyword = /sc_inject_direct\.exe/ nocase ascii wide
                        $string9_acheron_offensive_tool_keyword = /sc_inject_indirect\.exe/ nocase ascii wide

    condition:
        any of them
}