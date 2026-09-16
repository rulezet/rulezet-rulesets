rule ropfuscator
{
    meta:
        description = "Detection patterns for the tool 'ropfuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ropfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " ropfuscator" nocase ascii wide
                        $string2 = "/ropfuscator" nocase ascii wide
                        $string3 = /ROPEngine\.cpp/ nocase ascii wide
                        $string4 = "ropfuscator " nocase ascii wide
                        $string5 = "ROPfuscator" nocase ascii wide
                        $string6 = "ropfuscator-" nocase ascii wide
                        $string7 = /ropfuscator\./ nocase ascii wide

    condition:
        any of them
}