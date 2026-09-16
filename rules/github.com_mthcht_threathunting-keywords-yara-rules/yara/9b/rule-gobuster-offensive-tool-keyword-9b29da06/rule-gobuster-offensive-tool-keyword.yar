rule rule_gobuster_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gobuster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gobuster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gobuster_offensive_tool_keyword = /\/gobuster\.git/
                        $string2_gobuster_offensive_tool_keyword = "/gobuster/"
                        $string3_gobuster_offensive_tool_keyword = "/gobusterdir/"
                        $string4_gobuster_offensive_tool_keyword = "/gobusterdns/"
                        $string5_gobuster_offensive_tool_keyword = "/gobustergcs/"
                        $string6_gobuster_offensive_tool_keyword = "/libgobuster"
                        $string7_gobuster_offensive_tool_keyword = "/OJ/gobuster"
                        $string8_gobuster_offensive_tool_keyword = "gobuster dir "
                        $string9_gobuster_offensive_tool_keyword = "gobuster dns"
                        $string10_gobuster_offensive_tool_keyword = "gobuster fuzz -"
                        $string11_gobuster_offensive_tool_keyword = "gobuster gcs "
                        $string12_gobuster_offensive_tool_keyword = "gobuster s3 "
                        $string13_gobuster_offensive_tool_keyword = "gobuster tftp "
                        $string14_gobuster_offensive_tool_keyword = "gobuster vhost -u "
                        $string15_gobuster_offensive_tool_keyword = "gobuster vhost"
                        $string16_gobuster_offensive_tool_keyword = "gobuster"
                        $string17_gobuster_offensive_tool_keyword = /gobuster_.{0,1000}\.tar\.gz/
                        $string18_gobuster_offensive_tool_keyword = /gobuster_.{0,1000}\.zip/
                        $string19_gobuster_offensive_tool_keyword = "gobusterfuzz"
                        $string20_gobuster_offensive_tool_keyword = "gobustertftp"
                        $string21_gobuster_offensive_tool_keyword = "install gobuster"
                        $string22_gobuster_offensive_tool_keyword = /\-w\s.{0,1000}wordlists.{0,1000}\.txt/

    condition:
        any of them
}