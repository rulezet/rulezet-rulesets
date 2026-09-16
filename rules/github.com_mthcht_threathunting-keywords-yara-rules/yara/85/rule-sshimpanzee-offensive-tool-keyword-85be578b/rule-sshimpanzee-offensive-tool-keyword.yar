rule rule_sshimpanzee_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sshimpanzee' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshimpanzee"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sshimpanzee_offensive_tool_keyword = /\.\/sshimpanzee/
                        $string2_sshimpanzee_offensive_tool_keyword = /\/bin\/proxy_cli\.py/
                        $string3_sshimpanzee_offensive_tool_keyword = /\/sshimpanzee\.git/ nocase ascii wide
                        $string4_sshimpanzee_offensive_tool_keyword = /blog\.lexfo\.fr\/sshimpanzee\.html/ nocase ascii wide
                        $string5_sshimpanzee_offensive_tool_keyword = /dns\.lexfo\.fr/ nocase ascii wide
                        $string6_sshimpanzee_offensive_tool_keyword = /git\sreset\seb88d07c43afe407094e7d609248d85a15e148ef\s\-\-hard.{0,1000}\srm\s\-f\ssshd/ nocase ascii wide
                        $string7_sshimpanzee_offensive_tool_keyword = "lexfo/sshimpanzee" nocase ascii wide
                        $string8_sshimpanzee_offensive_tool_keyword = /MODE\=.{0,1000}\sREMOTE\=.{0,1000}sshimpanzee/ nocase ascii wide
                        $string9_sshimpanzee_offensive_tool_keyword = /ProxyCommand\=nc\s\-lp\s8080\s\-s\s127\.0\.0\.1/ nocase ascii wide
                        $string10_sshimpanzee_offensive_tool_keyword = "sshimpanzee --" nocase ascii wide
                        $string11_sshimpanzee_offensive_tool_keyword = /sshimpanzee\:127\.0\.0\.1\:/ nocase ascii wide
                        $string12_sshimpanzee_offensive_tool_keyword = /sshimpanzee\-1\.1\-exp/ nocase ascii wide
                        $string13_sshimpanzee_offensive_tool_keyword = "sshimpanzee-main" nocase ascii wide

    condition:
        any of them
}