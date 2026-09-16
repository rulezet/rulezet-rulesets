rule SharpGmailC2
{
    meta:
        description = "Detection patterns for the tool 'SharpGmailC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGmailC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sgmailC2\.exe/ nocase ascii wide
                        $string2 = /\/gmailC2\.exe/ nocase ascii wide
                        $string3 = /\/SharpGmailC2\.git/ nocase ascii wide
                        $string4 = /\\gmailC2\.exe/ nocase ascii wide
                        $string5 = /\\SharpGmailC2/ nocase ascii wide
                        $string6 = "946D24E4-201B-4D51-AF9A-3190266E0E1B" nocase ascii wide
                        $string7 = "CE895D82-85AA-41D9-935A-9625312D87D0" nocase ascii wide
                        $string8 = /GmailC2\.csproj/ nocase ascii wide
                        $string9 = /OrderFromC2\s\=\sReadEmail\(\)/ nocase ascii wide
                        $string10 = "reveng007/SharpGmailC2" nocase ascii wide
                        $string11 = "SharpGmailC2-main" nocase ascii wide

    condition:
        any of them
}