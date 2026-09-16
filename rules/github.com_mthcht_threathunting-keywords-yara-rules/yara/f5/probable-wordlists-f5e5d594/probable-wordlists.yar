rule Probable_Wordlists
{
    meta:
        description = "Detection patterns for the tool 'Probable-Wordlists' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Probable-Wordlists"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Probable-Wordlists" nocase ascii wide
                        $string2 = "Probable-Wordlists" nocase ascii wide
                        $string3 = "Real-Passwords" nocase ascii wide
                        $string4 = /Top109Million\-probable\-v2\.txt/ nocase ascii wide
                        $string5 = /Top12Thousand\-probable\-v2\.txt/ nocase ascii wide
                        $string6 = /Top1575\-probable\-v2\.txt/ nocase ascii wide
                        $string7 = /Top1pt6Million\-probable\-v2\.txt/ nocase ascii wide
                        $string8 = /Top207\-probable\-v2\.txt/ nocase ascii wide
                        $string9 = /Top29Million\-probable\-v2\.txt/ nocase ascii wide
                        $string10 = /Top2Billion\-probable\-v2\.txt/ nocase ascii wide
                        $string11 = /Top304Thousand\-probable\-v2\.txt/ nocase ascii wide
                        $string12 = /Top353Million\-probable\-v2\.txt/ nocase ascii wide

    condition:
        any of them
}