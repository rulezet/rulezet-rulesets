rule ntdissector
{
    meta:
        description = "Detection patterns for the tool 'ntdissector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntdissector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-ntds\sNTDS\.dit\s\s\-filters/ nocase ascii wide
                        $string2 = /\s\-ntds\sNTDS\.dit\s\-system\sSYSTEM\s\-outputdir\s\// nocase ascii wide
                        $string3 = /\.\/ntdissector/
                        $string4 = /\/\.ntdissector/
                        $string5 = /\/ntdissector\.git/ nocase ascii wide
                        $string6 = "/ntdissector/"
                        $string7 = /dBCSPwd.{0,1000}aad3b435b51404eeaad3b435b51404ee/ nocase ascii wide
                        $string8 = "ntdissector -" nocase ascii wide
                        $string9 = "ntdissector-main" nocase ascii wide
                        $string10 = /ntds\/ntds\.py/ nocase ascii wide
                        $string11 = "synacktiv/ntdissector" nocase ascii wide
                        $string12 = /user_to_secretsdump\.py/ nocase ascii wide

    condition:
        any of them
}