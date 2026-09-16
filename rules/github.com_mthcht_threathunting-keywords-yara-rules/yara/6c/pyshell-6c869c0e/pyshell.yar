rule pyshell
{
    meta:
        description = "Detection patterns for the tool 'pyshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/PyShell\s/
                        $string2 = "/JoelGMSec/PyShell" nocase ascii wide
                        $string3 = /\/Shells\/shell\.aspx/ nocase ascii wide
                        $string4 = /\/Shells\/shell\.jsp/ nocase ascii wide
                        $string5 = /\/Shells\/shell\.php/ nocase ascii wide
                        $string6 = /\/Shells\/shell\.py/ nocase ascii wide
                        $string7 = /\/Shells\/shell\.sh/ nocase ascii wide
                        $string8 = /\/Shells\/tomcat\.war/ nocase ascii wide
                        $string9 = /\/Shells\/wordpress\.zip/ nocase ascii wide

    condition:
        any of them
}