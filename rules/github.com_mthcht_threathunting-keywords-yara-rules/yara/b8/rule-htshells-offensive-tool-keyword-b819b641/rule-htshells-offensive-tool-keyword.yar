rule rule_htshells_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'htshells' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "htshells"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_htshells_offensive_tool_keyword = /\sprepare\.sh\sshell\/mod_.{0,1000}\.htaccess/
                        $string2_htshells_offensive_tool_keyword = /\/htshells\.git/ nocase ascii wide
                        $string3_htshells_offensive_tool_keyword = /\/prepare\.sh\sshell\/mod_.{0,1000}\.htaccess/
                        $string4_htshells_offensive_tool_keyword = "htshells-master" nocase ascii wide
                        $string5_htshells_offensive_tool_keyword = /http\:\/\/.{0,1000}\/\.htaccess\?c\=cmd/ nocase ascii wide
                        $string6_htshells_offensive_tool_keyword = /http\:\/\/.{0,1000}\/\.htaccess\?c\=uname\s\-a/ nocase ascii wide
                        $string7_htshells_offensive_tool_keyword = /https\:\/\/.{0,1000}\/\.htaccess\?c\=cmd/ nocase ascii wide
                        $string8_htshells_offensive_tool_keyword = /https\:\/\/.{0,1000}\/\.htaccess\?c\=uname\s\-a/ nocase ascii wide
                        $string9_htshells_offensive_tool_keyword = /mod_auth_remote\.phish\.htaccess/ nocase ascii wide
                        $string10_htshells_offensive_tool_keyword = /mod_caucho\.shell\.htaccess/ nocase ascii wide
                        $string11_htshells_offensive_tool_keyword = /mod_cgi\.shell\.bash\.htaccess/
                        $string12_htshells_offensive_tool_keyword = /mod_cgi\.shell\.bind\.htaccess/ nocase ascii wide
                        $string13_htshells_offensive_tool_keyword = /mod_cgi\.shell\.windows\.htaccess/ nocase ascii wide
                        $string14_htshells_offensive_tool_keyword = /mod_mono\.shell\.htaccess/ nocase ascii wide
                        $string15_htshells_offensive_tool_keyword = /mod_multi\.shell\.htaccess/ nocase ascii wide
                        $string16_htshells_offensive_tool_keyword = /mod_perl\.embperl\.shell\.htaccess/ nocase ascii wide
                        $string17_htshells_offensive_tool_keyword = /mod_perl\.IPP\.shell\.htaccess/ nocase ascii wide
                        $string18_htshells_offensive_tool_keyword = /mod_perl\.Mason\.shell\.htaccess/ nocase ascii wide
                        $string19_htshells_offensive_tool_keyword = /mod_perl\.shell\.htaccess/ nocase ascii wide
                        $string20_htshells_offensive_tool_keyword = /mod_php\.shell\.htaccess/ nocase ascii wide
                        $string21_htshells_offensive_tool_keyword = /mod_php\.shell2\.htaccess/ nocase ascii wide
                        $string22_htshells_offensive_tool_keyword = /mod_php\.stealth\-shell\.htaccess/ nocase ascii wide
                        $string23_htshells_offensive_tool_keyword = /mod_python\.shell\.htaccess/ nocase ascii wide
                        $string24_htshells_offensive_tool_keyword = /mod_rivet\.shell\.htaccess/ nocase ascii wide
                        $string25_htshells_offensive_tool_keyword = /mod_ruby\.shell\.htaccess/ nocase ascii wide
                        $string26_htshells_offensive_tool_keyword = /mod_sendmail\.rce\.htaccess/ nocase ascii wide
                        $string27_htshells_offensive_tool_keyword = "wireghoul/htshells" nocase ascii wide

    condition:
        any of them
}