rule sshimpanzee
{
    meta:
        description = "Detection patterns for the tool 'sshimpanzee' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshimpanzee"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/sshimpanzee/
                        $string2 = /\/bin\/proxy_cli\.py/
                        $string3 = /\/sshimpanzee\.git/ nocase ascii wide
                        $string4 = /blog\.lexfo\.fr\/sshimpanzee\.html/ nocase ascii wide
                        $string5 = /dns\.lexfo\.fr/ nocase ascii wide
                        $string6 = /git\sreset\seb88d07c43afe407094e7d609248d85a15e148ef\s\-\-hard.{0,1000}\srm\s\-f\ssshd/ nocase ascii wide
                        $string7 = "lexfo/sshimpanzee" nocase ascii wide
                        $string8 = /MODE\=.{0,1000}\sREMOTE\=.{0,1000}sshimpanzee/ nocase ascii wide
                        $string9 = /ProxyCommand\=nc\s\-lp\s8080\s\-s\s127\.0\.0\.1/ nocase ascii wide
                        $string10 = "sshimpanzee --" nocase ascii wide
                        $string11 = /sshimpanzee\:127\.0\.0\.1\:/ nocase ascii wide
                        $string12 = /sshimpanzee\-1\.1\-exp/ nocase ascii wide
                        $string13 = "sshimpanzee-main" nocase ascii wide

    condition:
        any of them
}