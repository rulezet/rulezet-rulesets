rule ReverseTCPShell
{
    meta:
        description = "Detection patterns for the tool 'ReverseTCPShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ReverseTCPShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ReverseTCPShell" nocase ascii wide
                        $string2 = "function Base64_Obfuscation" nocase ascii wide
                        $string3 = "function BXOR_Obfuscation" nocase ascii wide
                        $string4 = /ReverseTCP\.ps1/ nocase ascii wide
                        $string5 = "ReverseTCPShell-main" nocase ascii wide

    condition:
        any of them
}