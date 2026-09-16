rule rule_pyshell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pyshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pyshell_offensive_tool_keyword = /\.\/PyShell\s/
                        $string2_pyshell_offensive_tool_keyword = "/JoelGMSec/PyShell" nocase ascii wide
                        $string3_pyshell_offensive_tool_keyword = /\/Shells\/shell\.aspx/ nocase ascii wide
                        $string4_pyshell_offensive_tool_keyword = /\/Shells\/shell\.jsp/ nocase ascii wide
                        $string5_pyshell_offensive_tool_keyword = /\/Shells\/shell\.php/ nocase ascii wide
                        $string6_pyshell_offensive_tool_keyword = /\/Shells\/shell\.py/ nocase ascii wide
                        $string7_pyshell_offensive_tool_keyword = /\/Shells\/shell\.sh/ nocase ascii wide
                        $string8_pyshell_offensive_tool_keyword = /\/Shells\/tomcat\.war/ nocase ascii wide
                        $string9_pyshell_offensive_tool_keyword = /\/Shells\/wordpress\.zip/ nocase ascii wide

    condition:
        any of them
}