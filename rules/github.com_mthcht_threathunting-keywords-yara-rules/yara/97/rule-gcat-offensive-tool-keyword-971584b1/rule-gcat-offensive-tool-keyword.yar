rule rule_gcat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gcat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gcat_offensive_tool_keyword = " -exec-shellcode " nocase ascii wide
                        $string2_gcat_offensive_tool_keyword = /\sgcat\.py\s\-/ nocase ascii wide
                        $string3_gcat_offensive_tool_keyword = /\/gcat\.git/ nocase ascii wide
                        $string4_gcat_offensive_tool_keyword = /\/gcat\.py/ nocase ascii wide
                        $string5_gcat_offensive_tool_keyword = "byt3bl33d3r/gcat" nocase ascii wide
                        $string6_gcat_offensive_tool_keyword = /gcat.{0,1000}implant\.py/ nocase ascii wide
                        $string7_gcat_offensive_tool_keyword = /gcat\.is\.the\.shit\@gmail\.com/ nocase ascii wide
                        $string8_gcat_offensive_tool_keyword = "-start-keylogger" nocase ascii wide
                        $string9_gcat_offensive_tool_keyword = "-stop-keylogger" nocase ascii wide

    condition:
        any of them
}