rule SocialBox_Termux
{
    meta:
        description = "Detection patterns for the tool 'SocialBox-Termux' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SocialBox-Termux"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sinstabf\.py/ nocase ascii wide
                        $string2 = /\sinstainsane\.sh/ nocase ascii wide
                        $string3 = /\sinstall\-sb\.sh/ nocase ascii wide
                        $string4 = /\sinsTof\.py/ nocase ascii wide
                        $string5 = /\sSocialBox\.sh/ nocase ascii wide
                        $string6 = /\stweetshell\.sh/ nocase ascii wide
                        $string7 = /\/fb\-brute\.pl/ nocase ascii wide
                        $string8 = /\/Gemail\-Hack\.git/ nocase ascii wide
                        $string9 = /\/insta\-bf\.git/ nocase ascii wide
                        $string10 = /\/instabf\.py/ nocase ascii wide
                        $string11 = /\/instainsane\.git/ nocase ascii wide
                        $string12 = /\/instainsane\.sh/ nocase ascii wide
                        $string13 = /\/install\-sb\.sh/ nocase ascii wide
                        $string14 = /\/insTof\.py/ nocase ascii wide
                        $string15 = /\/SocialBox\.sh/ nocase ascii wide
                        $string16 = "/SocialBox-Termux" nocase ascii wide
                        $string17 = "/Sup3r-Us3r/scripts/" nocase ascii wide
                        $string18 = /\/tweetshell\.sh/ nocase ascii wide
                        $string19 = "/umeshshinde19/instainsane" nocase ascii wide
                        $string20 = "apt-get -y install tor " nocase ascii wide
                        $string21 = /Brute\-force\-Instagram\-.{0,1000}\.git/ nocase ascii wide
                        $string22 = "datr=80ZzUfKqDOjwL8pauwqMjHTa" nocase ascii wide
                        $string23 = /gemailhack\.py/ nocase ascii wide
                        $string24 = "Ha3MrX/Gemail-Hack" nocase ascii wide
                        $string25 = /Ox\-Bruter\.pl/ nocase ascii wide
                        $string26 = "thelinuxchoice/tweetshell"
                        $string27 = "Yuuup!! Pass Cracked" nocase ascii wide
                        $string28 = "ZxKmz4hXp6XKmTPg9lzgYxXN4sFr2pzo" nocase ascii wide

    condition:
        any of them
}