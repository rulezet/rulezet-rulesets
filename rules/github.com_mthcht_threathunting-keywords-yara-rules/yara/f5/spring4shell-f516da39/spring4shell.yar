rule Spring4Shell
{
    meta:
        description = "Detection patterns for the tool 'Spring4Shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spring4Shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/Spring4Shell-POC" nocase ascii wide
                        $string2 = "/Spring4Shell-POC" nocase ascii wide
                        $string3 = "/springshell-rce-poc" nocase ascii wide
                        $string4 = /curl\shttp.{0,1000}\/handling\-form\-submission\-complete\/rce\.jsp/ nocase ascii wide
                        $string5 = /docker\srun\s\-p\s.{0,1000}\sspring4shell/ nocase ascii wide
                        $string6 = /find\s\.\s\-name\sspring\-beans.{0,1000}\.jar/
                        $string7 = "TheGejr/SpringShell" nocase ascii wide
                        $string8 = /webshell\shttp.{0,1000}\/tomcatwar\.jsp\?cmd\=/ nocase ascii wide

    condition:
        any of them
}