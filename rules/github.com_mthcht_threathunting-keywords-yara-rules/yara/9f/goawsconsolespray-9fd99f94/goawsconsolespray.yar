rule GoAWSConsoleSpray
{
    meta:
        description = "Detection patterns for the tool 'GoAWSConsoleSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoAWSConsoleSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/GoAWSConsoleSpray/
                        $string2 = /\/GoAWSConsoleSpray\.git/ nocase ascii wide
                        $string3 = /\\GoAWSConsoleSpray\-master/ nocase ascii wide
                        $string4 = "53f349d9fefb61b435f3b257f63ec8720b92cc4446cc08455e53ba9c5ca8071c" nocase ascii wide
                        $string5 = "AWS Account Bruteforce Ratelimit! Sleeping for " nocase ascii wide
                        $string6 = "b096ce8b9397269012bccaef5a419211cb74d1157d4340453a3a39b68da7cf10" nocase ascii wide
                        $string7 = "bin/GoAWSConsoleSpray" nocase ascii wide
                        $string8 = "GoAWSConsoleSpray -" nocase ascii wide
                        $string9 = /GoAWSConsoleSpray\.exe/ nocase ascii wide
                        $string10 = "GoAWSConsoleSpray@latest" nocase ascii wide
                        $string11 = /GoAWSConsoleSpray\-master\.zip/ nocase ascii wide
                        $string12 = "WhiteOakSecurity/GoAWSConsoleSpray" nocase ascii wide

    condition:
        any of them
}