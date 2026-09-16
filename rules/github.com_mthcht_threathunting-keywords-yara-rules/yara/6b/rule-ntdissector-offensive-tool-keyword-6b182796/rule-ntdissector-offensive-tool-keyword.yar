rule rule_ntdissector_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ntdissector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntdissector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ntdissector_offensive_tool_keyword = /\s\-ntds\sNTDS\.dit\s\s\-filters/ nocase ascii wide
                        $string2_ntdissector_offensive_tool_keyword = /\s\-ntds\sNTDS\.dit\s\-system\sSYSTEM\s\-outputdir\s\// nocase ascii wide
                        $string3_ntdissector_offensive_tool_keyword = /\.\/ntdissector/
                        $string4_ntdissector_offensive_tool_keyword = /\/\.ntdissector/
                        $string5_ntdissector_offensive_tool_keyword = /\/ntdissector\.git/ nocase ascii wide
                        $string6_ntdissector_offensive_tool_keyword = "/ntdissector/"
                        $string7_ntdissector_offensive_tool_keyword = /dBCSPwd.{0,1000}aad3b435b51404eeaad3b435b51404ee/ nocase ascii wide
                        $string8_ntdissector_offensive_tool_keyword = "ntdissector -" nocase ascii wide
                        $string9_ntdissector_offensive_tool_keyword = "ntdissector-main" nocase ascii wide
                        $string10_ntdissector_offensive_tool_keyword = /ntds\/ntds\.py/ nocase ascii wide
                        $string11_ntdissector_offensive_tool_keyword = "synacktiv/ntdissector" nocase ascii wide
                        $string12_ntdissector_offensive_tool_keyword = /user_to_secretsdump\.py/ nocase ascii wide

    condition:
        any of them
}