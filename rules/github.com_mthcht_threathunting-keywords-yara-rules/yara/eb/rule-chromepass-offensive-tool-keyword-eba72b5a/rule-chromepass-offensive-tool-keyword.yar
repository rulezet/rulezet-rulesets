rule rule_chromepass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chromepass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chromepass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_chromepass_offensive_tool_keyword = ">ChromePass<" nocase ascii wide
                        $string2_chromepass_offensive_tool_keyword = "490139a7800992202ca46d3a69882b476014126fc3ed4143c184bcd7f76a5761" nocase ascii wide
                        $string3_chromepass_offensive_tool_keyword = "744e50af5566fa5ab70d4db70d35b3b89d75018e00b6b1e8e6280030482353bc" nocase ascii wide
                        $string4_chromepass_offensive_tool_keyword = "Chrome Password Recovery" nocase ascii wide
                        $string5_chromepass_offensive_tool_keyword = "Chrome Passwords List!" nocase ascii wide
                        $string6_chromepass_offensive_tool_keyword = /chromepass\.exe/ nocase ascii wide
                        $string7_chromepass_offensive_tool_keyword = /chromepass\.zip/ nocase ascii wide
                        $string8_chromepass_offensive_tool_keyword = "Load the passwords from another Windows user or external drive" nocase ascii wide
                        $string9_chromepass_offensive_tool_keyword = "Load the passwords of the current logged-on user" nocase ascii wide

    condition:
        any of them
}