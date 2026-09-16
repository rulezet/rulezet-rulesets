rule gobuster
{
    meta:
        description = "Detection patterns for the tool 'gobuster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gobuster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/gobuster\.git/
                        $string2 = "/gobuster/"
                        $string3 = "/gobusterdir/"
                        $string4 = "/gobusterdns/"
                        $string5 = "/gobustergcs/"
                        $string6 = "/libgobuster"
                        $string7 = "/OJ/gobuster"
                        $string8 = "gobuster dir "
                        $string9 = "gobuster dns"
                        $string10 = "gobuster fuzz -"
                        $string11 = "gobuster gcs "
                        $string12 = "gobuster s3 "
                        $string13 = "gobuster tftp "
                        $string14 = "gobuster vhost -u "
                        $string15 = "gobuster vhost"
                        $string16 = "gobuster"
                        $string17 = /gobuster_.{0,1000}\.tar\.gz/
                        $string18 = /gobuster_.{0,1000}\.zip/
                        $string19 = "gobusterfuzz"
                        $string20 = "gobustertftp"
                        $string21 = "install gobuster"
                        $string22 = /\-w\s.{0,1000}wordlists.{0,1000}\.txt/

    condition:
        any of them
}