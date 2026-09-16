rule rule_GoAWSConsoleSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GoAWSConsoleSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoAWSConsoleSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GoAWSConsoleSpray_offensive_tool_keyword = /\.\/GoAWSConsoleSpray/
                        $string2_GoAWSConsoleSpray_offensive_tool_keyword = /\/GoAWSConsoleSpray\.git/ nocase ascii wide
                        $string3_GoAWSConsoleSpray_offensive_tool_keyword = /\\GoAWSConsoleSpray\-master/ nocase ascii wide
                        $string4_GoAWSConsoleSpray_offensive_tool_keyword = "53f349d9fefb61b435f3b257f63ec8720b92cc4446cc08455e53ba9c5ca8071c" nocase ascii wide
                        $string5_GoAWSConsoleSpray_offensive_tool_keyword = "AWS Account Bruteforce Ratelimit! Sleeping for " nocase ascii wide
                        $string6_GoAWSConsoleSpray_offensive_tool_keyword = "b096ce8b9397269012bccaef5a419211cb74d1157d4340453a3a39b68da7cf10" nocase ascii wide
                        $string7_GoAWSConsoleSpray_offensive_tool_keyword = "bin/GoAWSConsoleSpray" nocase ascii wide
                        $string8_GoAWSConsoleSpray_offensive_tool_keyword = "GoAWSConsoleSpray -" nocase ascii wide
                        $string9_GoAWSConsoleSpray_offensive_tool_keyword = /GoAWSConsoleSpray\.exe/ nocase ascii wide
                        $string10_GoAWSConsoleSpray_offensive_tool_keyword = "GoAWSConsoleSpray@latest" nocase ascii wide
                        $string11_GoAWSConsoleSpray_offensive_tool_keyword = /GoAWSConsoleSpray\-master\.zip/ nocase ascii wide
                        $string12_GoAWSConsoleSpray_offensive_tool_keyword = "WhiteOakSecurity/GoAWSConsoleSpray" nocase ascii wide

    condition:
        any of them
}