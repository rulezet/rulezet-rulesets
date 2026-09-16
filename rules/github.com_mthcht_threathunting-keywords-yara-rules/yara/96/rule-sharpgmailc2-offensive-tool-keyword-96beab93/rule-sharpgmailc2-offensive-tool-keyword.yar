rule rule_SharpGmailC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpGmailC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGmailC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpGmailC2_offensive_tool_keyword = /\sgmailC2\.exe/ nocase ascii wide
                        $string2_SharpGmailC2_offensive_tool_keyword = /\/gmailC2\.exe/ nocase ascii wide
                        $string3_SharpGmailC2_offensive_tool_keyword = /\/SharpGmailC2\.git/ nocase ascii wide
                        $string4_SharpGmailC2_offensive_tool_keyword = /\\gmailC2\.exe/ nocase ascii wide
                        $string5_SharpGmailC2_offensive_tool_keyword = /\\SharpGmailC2/ nocase ascii wide
                        $string6_SharpGmailC2_offensive_tool_keyword = "946D24E4-201B-4D51-AF9A-3190266E0E1B" nocase ascii wide
                        $string7_SharpGmailC2_offensive_tool_keyword = "CE895D82-85AA-41D9-935A-9625312D87D0" nocase ascii wide
                        $string8_SharpGmailC2_offensive_tool_keyword = /GmailC2\.csproj/ nocase ascii wide
                        $string9_SharpGmailC2_offensive_tool_keyword = /OrderFromC2\s\=\sReadEmail\(\)/ nocase ascii wide
                        $string10_SharpGmailC2_offensive_tool_keyword = "reveng007/SharpGmailC2" nocase ascii wide
                        $string11_SharpGmailC2_offensive_tool_keyword = "SharpGmailC2-main" nocase ascii wide

    condition:
        any of them
}