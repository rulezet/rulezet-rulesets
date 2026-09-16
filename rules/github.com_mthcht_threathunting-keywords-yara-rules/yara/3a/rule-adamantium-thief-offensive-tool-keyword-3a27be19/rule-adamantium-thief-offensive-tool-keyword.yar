rule rule_Adamantium_Thief_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Adamantium-Thief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adamantium-Thief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Adamantium_Thief_offensive_tool_keyword = /\.exe\sBOOKMARKS/ nocase ascii wide
                        $string2_Adamantium_Thief_offensive_tool_keyword = /\.exe\sCOOKIES/ nocase ascii wide
                        $string3_Adamantium_Thief_offensive_tool_keyword = /\.exe\sCREDIT_CARDS/ nocase ascii wide
                        $string4_Adamantium_Thief_offensive_tool_keyword = /\/Adamantium\-Thief\.git/ nocase ascii wide
                        $string5_Adamantium_Thief_offensive_tool_keyword = /\/Stealer\.exe/ nocase ascii wide
                        $string6_Adamantium_Thief_offensive_tool_keyword = /\/Stealer\.sln/ nocase ascii wide
                        $string7_Adamantium_Thief_offensive_tool_keyword = /\\Stealer\.exe/ nocase ascii wide
                        $string8_Adamantium_Thief_offensive_tool_keyword = /\\Stealer\.sln/ nocase ascii wide
                        $string9_Adamantium_Thief_offensive_tool_keyword = /\\Stealer\\modules\\Passwords\.cs/ nocase ascii wide
                        $string10_Adamantium_Thief_offensive_tool_keyword = /\\Stealer\\Stealer\\modules\\/ nocase ascii wide
                        $string11_Adamantium_Thief_offensive_tool_keyword = "Adamantium-Thief-master" nocase ascii wide
                        $string12_Adamantium_Thief_offensive_tool_keyword = "Coded by LimerBoy <3" nocase ascii wide
                        $string13_Adamantium_Thief_offensive_tool_keyword = "E6104BC9-FEA9-4EE9-B919-28156C1F2EDE" nocase ascii wide
                        $string14_Adamantium_Thief_offensive_tool_keyword = "LimerBoy/Adamantium-Thief" nocase ascii wide
                        $string15_Adamantium_Thief_offensive_tool_keyword = /Please\sselect\scommand\s\[PASSWORDS\/HISTORY\/COOKIES\/AUTOFILL\/CREDIT_CARDS\/BOOKMARKS\]/ nocase ascii wide
                        $string16_Adamantium_Thief_offensive_tool_keyword = /Stealer\.exe\s/ nocase ascii wide

    condition:
        any of them
}