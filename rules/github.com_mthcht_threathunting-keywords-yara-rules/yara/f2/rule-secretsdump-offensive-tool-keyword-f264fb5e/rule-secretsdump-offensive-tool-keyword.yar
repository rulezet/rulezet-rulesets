rule rule_secretsdump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'secretsdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "secretsdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_secretsdump_offensive_tool_keyword = " -just-dc-ntlm " nocase ascii wide
                        $string2_secretsdump_offensive_tool_keyword = " -just-dc-user " nocase ascii wide
                        $string3_secretsdump_offensive_tool_keyword = /\/cached\-domain\-credentials\.html/ nocase ascii wide
                        $string4_secretsdump_offensive_tool_keyword = /\/decrypting\-lsa\-secrets\.html/ nocase ascii wide
                        $string5_secretsdump_offensive_tool_keyword = /\/syskey\-and\-sam\.html/ nocase ascii wide
                        $string6_secretsdump_offensive_tool_keyword = /\]\sDumping\ssecrets\sfor\:\s.{0,1000}Username\:\s/ nocase ascii wide
                        $string7_secretsdump_offensive_tool_keyword = "29cf4b68c34663281bebc94f62c92282ca351839032140fcb2b0266d44a8bc84" nocase ascii wide
                        $string8_secretsdump_offensive_tool_keyword = "fin3ss3g0d/secretsdump" nocase ascii wide
                        $string9_secretsdump_offensive_tool_keyword = /impacket\.examples\.secretsdump/ nocase ascii wide
                        $string10_secretsdump_offensive_tool_keyword = "Policy SPN target name validation might be restricting full DRSUAPI dump" nocase ascii wide
                        $string11_secretsdump_offensive_tool_keyword = /resuming\sa\sprevious\sNTDS\.DIT\sdump\ssession/ nocase ascii wide
                        $string12_secretsdump_offensive_tool_keyword = /secretsdump\.py/ nocase ascii wide

    condition:
        any of them
}