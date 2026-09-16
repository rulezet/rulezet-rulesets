rule BruteSploit
{
    meta:
        description = "Detection patterns for the tool 'BruteSploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BruteSploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Brutesploit" nocase ascii wide
                        $string2 = /\sMicrosploit\.sh/ nocase ascii wide
                        $string3 = /\.\/Brutesploit/
                        $string4 = /\.\/Microsploit/
                        $string5 = /\.\/Vegile/
                        $string6 = "/BruteSploit" nocase ascii wide
                        $string7 = /\/dirsearch\.py/ nocase ascii wide
                        $string8 = /\/instabrute\.py/ nocase ascii wide
                        $string9 = /\/Vegile\.git/ nocase ascii wide
                        $string10 = /Brutesploit\.git/ nocase ascii wide
                        $string11 = "BruteSploit/wlist/" nocase ascii wide
                        $string12 = /microsploit\.git/ nocase ascii wide
                        $string13 = /Password\-Default\/service\.txt/ nocase ascii wide
                        $string14 = "screetsec/Microsploit" nocase ascii wide
                        $string15 = "Vegile -" nocase ascii wide

    condition:
        any of them
}