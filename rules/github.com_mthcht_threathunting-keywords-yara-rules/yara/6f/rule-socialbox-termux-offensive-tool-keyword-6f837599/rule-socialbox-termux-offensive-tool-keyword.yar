rule rule_SocialBox_Termux_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SocialBox-Termux' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SocialBox-Termux"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SocialBox_Termux_offensive_tool_keyword = /\sinstabf\.py/ nocase ascii wide
                        $string2_SocialBox_Termux_offensive_tool_keyword = /\sinstainsane\.sh/ nocase ascii wide
                        $string3_SocialBox_Termux_offensive_tool_keyword = /\sinstall\-sb\.sh/ nocase ascii wide
                        $string4_SocialBox_Termux_offensive_tool_keyword = /\sinsTof\.py/ nocase ascii wide
                        $string5_SocialBox_Termux_offensive_tool_keyword = /\sSocialBox\.sh/ nocase ascii wide
                        $string6_SocialBox_Termux_offensive_tool_keyword = /\stweetshell\.sh/ nocase ascii wide
                        $string7_SocialBox_Termux_offensive_tool_keyword = /\/fb\-brute\.pl/ nocase ascii wide
                        $string8_SocialBox_Termux_offensive_tool_keyword = /\/Gemail\-Hack\.git/ nocase ascii wide
                        $string9_SocialBox_Termux_offensive_tool_keyword = /\/insta\-bf\.git/ nocase ascii wide
                        $string10_SocialBox_Termux_offensive_tool_keyword = /\/instabf\.py/ nocase ascii wide
                        $string11_SocialBox_Termux_offensive_tool_keyword = /\/instainsane\.git/ nocase ascii wide
                        $string12_SocialBox_Termux_offensive_tool_keyword = /\/instainsane\.sh/ nocase ascii wide
                        $string13_SocialBox_Termux_offensive_tool_keyword = /\/install\-sb\.sh/ nocase ascii wide
                        $string14_SocialBox_Termux_offensive_tool_keyword = /\/insTof\.py/ nocase ascii wide
                        $string15_SocialBox_Termux_offensive_tool_keyword = /\/SocialBox\.sh/ nocase ascii wide
                        $string16_SocialBox_Termux_offensive_tool_keyword = "/SocialBox-Termux" nocase ascii wide
                        $string17_SocialBox_Termux_offensive_tool_keyword = "/Sup3r-Us3r/scripts/" nocase ascii wide
                        $string18_SocialBox_Termux_offensive_tool_keyword = /\/tweetshell\.sh/ nocase ascii wide
                        $string19_SocialBox_Termux_offensive_tool_keyword = "/umeshshinde19/instainsane" nocase ascii wide
                        $string20_SocialBox_Termux_offensive_tool_keyword = "apt-get -y install tor " nocase ascii wide
                        $string21_SocialBox_Termux_offensive_tool_keyword = /Brute\-force\-Instagram\-.{0,1000}\.git/ nocase ascii wide
                        $string22_SocialBox_Termux_offensive_tool_keyword = "datr=80ZzUfKqDOjwL8pauwqMjHTa" nocase ascii wide
                        $string23_SocialBox_Termux_offensive_tool_keyword = /gemailhack\.py/ nocase ascii wide
                        $string24_SocialBox_Termux_offensive_tool_keyword = "Ha3MrX/Gemail-Hack" nocase ascii wide
                        $string25_SocialBox_Termux_offensive_tool_keyword = /Ox\-Bruter\.pl/ nocase ascii wide
                        $string26_SocialBox_Termux_offensive_tool_keyword = "thelinuxchoice/tweetshell"
                        $string27_SocialBox_Termux_offensive_tool_keyword = "Yuuup!! Pass Cracked" nocase ascii wide
                        $string28_SocialBox_Termux_offensive_tool_keyword = "ZxKmz4hXp6XKmTPg9lzgYxXN4sFr2pzo" nocase ascii wide

    condition:
        any of them
}