rule Adamantium_Thief
{
    meta:
        description = "Detection patterns for the tool 'Adamantium-Thief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adamantium-Thief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\sBOOKMARKS/ nocase ascii wide
                        $string2 = /\.exe\sCOOKIES/ nocase ascii wide
                        $string3 = /\.exe\sCREDIT_CARDS/ nocase ascii wide
                        $string4 = /\/Adamantium\-Thief\.git/ nocase ascii wide
                        $string5 = /\/Stealer\.exe/ nocase ascii wide
                        $string6 = /\/Stealer\.sln/ nocase ascii wide
                        $string7 = /\\Stealer\.exe/ nocase ascii wide
                        $string8 = /\\Stealer\.sln/ nocase ascii wide
                        $string9 = /\\Stealer\\modules\\Passwords\.cs/ nocase ascii wide
                        $string10 = /\\Stealer\\Stealer\\modules\\/ nocase ascii wide
                        $string11 = "Adamantium-Thief-master" nocase ascii wide
                        $string12 = "Coded by LimerBoy <3" nocase ascii wide
                        $string13 = "E6104BC9-FEA9-4EE9-B919-28156C1F2EDE" nocase ascii wide
                        $string14 = "LimerBoy/Adamantium-Thief" nocase ascii wide
                        $string15 = /Please\sselect\scommand\s\[PASSWORDS\/HISTORY\/COOKIES\/AUTOFILL\/CREDIT_CARDS\/BOOKMARKS\]/ nocase ascii wide
                        $string16 = /Stealer\.exe\s/ nocase ascii wide

    condition:
        any of them
}