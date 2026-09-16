rule rule_BruteSploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BruteSploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BruteSploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BruteSploit_offensive_tool_keyword = " Brutesploit" nocase ascii wide
                        $string2_BruteSploit_offensive_tool_keyword = /\sMicrosploit\.sh/ nocase ascii wide
                        $string3_BruteSploit_offensive_tool_keyword = /\.\/Brutesploit/
                        $string4_BruteSploit_offensive_tool_keyword = /\.\/Microsploit/
                        $string5_BruteSploit_offensive_tool_keyword = /\.\/Vegile/
                        $string6_BruteSploit_offensive_tool_keyword = "/BruteSploit" nocase ascii wide
                        $string7_BruteSploit_offensive_tool_keyword = /\/dirsearch\.py/ nocase ascii wide
                        $string8_BruteSploit_offensive_tool_keyword = /\/instabrute\.py/ nocase ascii wide
                        $string9_BruteSploit_offensive_tool_keyword = /\/Vegile\.git/ nocase ascii wide
                        $string10_BruteSploit_offensive_tool_keyword = /Brutesploit\.git/ nocase ascii wide
                        $string11_BruteSploit_offensive_tool_keyword = "BruteSploit/wlist/" nocase ascii wide
                        $string12_BruteSploit_offensive_tool_keyword = /microsploit\.git/ nocase ascii wide
                        $string13_BruteSploit_offensive_tool_keyword = /Password\-Default\/service\.txt/ nocase ascii wide
                        $string14_BruteSploit_offensive_tool_keyword = "screetsec/Microsploit" nocase ascii wide
                        $string15_BruteSploit_offensive_tool_keyword = "Vegile -" nocase ascii wide

    condition:
        any of them
}