rule rule_Spring4Shell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Spring4Shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spring4Shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Spring4Shell_offensive_tool_keyword = "/Spring4Shell-POC" nocase ascii wide
                        $string2_Spring4Shell_offensive_tool_keyword = "/Spring4Shell-POC" nocase ascii wide
                        $string3_Spring4Shell_offensive_tool_keyword = "/springshell-rce-poc" nocase ascii wide
                        $string4_Spring4Shell_offensive_tool_keyword = /curl\shttp.{0,1000}\/handling\-form\-submission\-complete\/rce\.jsp/ nocase ascii wide
                        $string5_Spring4Shell_offensive_tool_keyword = /docker\srun\s\-p\s.{0,1000}\sspring4shell/ nocase ascii wide
                        $string6_Spring4Shell_offensive_tool_keyword = /find\s\.\s\-name\sspring\-beans.{0,1000}\.jar/
                        $string7_Spring4Shell_offensive_tool_keyword = "TheGejr/SpringShell" nocase ascii wide
                        $string8_Spring4Shell_offensive_tool_keyword = /webshell\shttp.{0,1000}\/tomcatwar\.jsp\?cmd\=/ nocase ascii wide

    condition:
        any of them
}