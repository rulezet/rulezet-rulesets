rule rule_Token_Impersonation_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Token-Impersonation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Token-Impersonation"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Token_Impersonation_offensive_tool_keyword = " -Steal -ProcessID " nocase ascii wide
                        $string2_Token_Impersonation_offensive_tool_keyword = /\sToken\-Impersonation\.ps1/ nocase ascii wide
                        $string3_Token_Impersonation_offensive_tool_keyword = /\$StealToken/ nocase ascii wide
                        $string4_Token_Impersonation_offensive_tool_keyword = /\/Token\-Impersonation\.git/ nocase ascii wide
                        $string5_Token_Impersonation_offensive_tool_keyword = /\/Token\-Impersonation\.ps1/ nocase ascii wide
                        $string6_Token_Impersonation_offensive_tool_keyword = /\[\+\]\sImpersonation\ssuccessful\susing\stoken\sfrom\sPID\s/ nocase ascii wide
                        $string7_Token_Impersonation_offensive_tool_keyword = /\\Token\-Impersonation\.ps1/ nocase ascii wide
                        $string8_Token_Impersonation_offensive_tool_keyword = "42e10ec6f9a5276060bade151ccd929325daa8ac8910ee26de5e6eebe10f77aa" nocase ascii wide
                        $string9_Token_Impersonation_offensive_tool_keyword = "Leo4j/Token-Impersonation" nocase ascii wide
                        $string10_Token_Impersonation_offensive_tool_keyword = "Token-Impersonation -MakeToken" nocase ascii wide
                        $string11_Token_Impersonation_offensive_tool_keyword = "Token-Impersonation -Rev2Self" nocase ascii wide
                        $string12_Token_Impersonation_offensive_tool_keyword = "Token-Impersonation -Steal" nocase ascii wide

    condition:
        any of them
}