rule htshells
{
    meta:
        description = "Detection patterns for the tool 'htshells' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "htshells"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sprepare\.sh\sshell\/mod_.{0,1000}\.htaccess/
                        $string2 = /\/htshells\.git/ nocase ascii wide
                        $string3 = /\/prepare\.sh\sshell\/mod_.{0,1000}\.htaccess/
                        $string4 = "htshells-master" nocase ascii wide
                        $string5 = /http\:\/\/.{0,1000}\/\.htaccess\?c\=cmd/ nocase ascii wide
                        $string6 = /http\:\/\/.{0,1000}\/\.htaccess\?c\=uname\s\-a/ nocase ascii wide
                        $string7 = /https\:\/\/.{0,1000}\/\.htaccess\?c\=cmd/ nocase ascii wide
                        $string8 = /https\:\/\/.{0,1000}\/\.htaccess\?c\=uname\s\-a/ nocase ascii wide
                        $string9 = /mod_auth_remote\.phish\.htaccess/ nocase ascii wide
                        $string10 = /mod_caucho\.shell\.htaccess/ nocase ascii wide
                        $string11 = /mod_cgi\.shell\.bash\.htaccess/
                        $string12 = /mod_cgi\.shell\.bind\.htaccess/ nocase ascii wide
                        $string13 = /mod_cgi\.shell\.windows\.htaccess/ nocase ascii wide
                        $string14 = /mod_mono\.shell\.htaccess/ nocase ascii wide
                        $string15 = /mod_multi\.shell\.htaccess/ nocase ascii wide
                        $string16 = /mod_perl\.embperl\.shell\.htaccess/ nocase ascii wide
                        $string17 = /mod_perl\.IPP\.shell\.htaccess/ nocase ascii wide
                        $string18 = /mod_perl\.Mason\.shell\.htaccess/ nocase ascii wide
                        $string19 = /mod_perl\.shell\.htaccess/ nocase ascii wide
                        $string20 = /mod_php\.shell\.htaccess/ nocase ascii wide
                        $string21 = /mod_php\.shell2\.htaccess/ nocase ascii wide
                        $string22 = /mod_php\.stealth\-shell\.htaccess/ nocase ascii wide
                        $string23 = /mod_python\.shell\.htaccess/ nocase ascii wide
                        $string24 = /mod_rivet\.shell\.htaccess/ nocase ascii wide
                        $string25 = /mod_ruby\.shell\.htaccess/ nocase ascii wide
                        $string26 = /mod_sendmail\.rce\.htaccess/ nocase ascii wide
                        $string27 = "wireghoul/htshells" nocase ascii wide

    condition:
        any of them
}