rule rule_ReverseTCPShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ReverseTCPShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ReverseTCPShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ReverseTCPShell_offensive_tool_keyword = "/ReverseTCPShell" nocase ascii wide
                        $string2_ReverseTCPShell_offensive_tool_keyword = "function Base64_Obfuscation" nocase ascii wide
                        $string3_ReverseTCPShell_offensive_tool_keyword = "function BXOR_Obfuscation" nocase ascii wide
                        $string4_ReverseTCPShell_offensive_tool_keyword = /ReverseTCP\.ps1/ nocase ascii wide
                        $string5_ReverseTCPShell_offensive_tool_keyword = "ReverseTCPShell-main" nocase ascii wide

    condition:
        any of them
}