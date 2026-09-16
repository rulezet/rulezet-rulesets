rule OWASP_rules
{
    meta:
        description = "Detection patterns for the tool 'OWASP rules' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OWASP rules"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "\"small web shell by zaco" nocase ascii wide
                        $string2 = /\/tmp\/evil\.sh/
                        $string3 = /\-\:\[GreenwooD\]\:\-\sWinX\sShell/ nocase ascii wide
                        $string4 = /\<h1\>\.\:NCC\:\.\sShell\sv/ nocase ascii wide
                        $string5 = /\<H1\>\<center\>\-\=\[\+\]\sIDBTEAM\sSHELLS/ nocase ascii wide
                        $string6 = "<h2>Laudanum Tools" nocase ascii wide
                        $string7 = /\<head\>\<title\>Wardom\s\|\sNe\sMutlu\sT/ nocase ascii wide
                        $string8 = "<title>Sosyete Safe Mode Bypass Shell -" nocase ascii wide
                        $string9 = "<title>SyRiAn Sh3ll ~" nocase ascii wide
                        $string10 = "<title>WebRoot Hack Tools\"" nocase ascii wide
                        $string11 = /\=\[\s1n73ct10n\sprivat\sshell\s\]\=/ nocase ascii wide
                        $string12 = /\-\-\=\=\[\[\sAndela\sYuwono\sPriv8\sShell\s\]\]\=\=\-\-/ nocase ascii wide
                        $string13 = "0byt3m1n1-V2" nocase ascii wide
                        $string14 = "BloodSecurity Hackers Shell" nocase ascii wide
                        $string15 = /chmod\s\+x\sevil\.php/
                        $string16 = /Con7ext\sShell\sV\.2/ nocase ascii wide
                        $string17 = "CUPLIS BYPASSS SHELL" nocase ascii wide
                        $string18 = "Dive Shell - Emperor Hacking Team" nocase ascii wide
                        $string19 = "G-Security Webshell" nocase ascii wide
                        $string20 = /h4ntu\sshell\s\[powered\sby\stsoi\]/ nocase ascii wide
                        $string21 = "Laudanum PHP File Browser" nocase ascii wide
                        $string22 = "Laudanum PHP Hostname by IP Lookup" nocase ascii wide
                        $string23 = "Laudanum PHP Proxy" nocase ascii wide
                        $string24 = "Laudanum PHP Shell Access" nocase ascii wide
                        $string25 = "Loader'z WEB shell" nocase ascii wide
                        $string26 = /Lolipop\.php\s\-\sEdited\sBy\sKingDefacer/ nocase ascii wide
                        $string27 = "Simple PHP backdoor by DK" nocase ascii wide
                        $string28 = "SimShell - Simorgh Security MGZ" nocase ascii wide
                        $string29 = "Small Shell - Edited By KingDefacer" nocase ascii wide
                        $string30 = /Yourman\.sh\sMini\sShell/
                        $string31 = /ZEROSHELL\s\|\sZEROSTORE/ nocase ascii wide

    condition:
        any of them
}