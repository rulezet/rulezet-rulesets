rule rule_pe_to_shellcode_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pe_to_shellcode' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pe_to_shellcode"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pe_to_shellcode_offensive_tool_keyword = "/pe_to_shellcode" nocase ascii wide
                        $string2_pe_to_shellcode_offensive_tool_keyword = "/pe2shc/" nocase ascii wide
                        $string3_pe_to_shellcode_offensive_tool_keyword = /pe2shc\.exe\s/ nocase ascii wide

    condition:
        any of them
}