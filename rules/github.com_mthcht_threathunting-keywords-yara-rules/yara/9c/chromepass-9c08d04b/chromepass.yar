rule chromepass
{
    meta:
        description = "Detection patterns for the tool 'chromepass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chromepass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = ">ChromePass<" nocase ascii wide
                        $string2 = "490139a7800992202ca46d3a69882b476014126fc3ed4143c184bcd7f76a5761" nocase ascii wide
                        $string3 = "744e50af5566fa5ab70d4db70d35b3b89d75018e00b6b1e8e6280030482353bc" nocase ascii wide
                        $string4 = "Chrome Password Recovery" nocase ascii wide
                        $string5 = "Chrome Passwords List!" nocase ascii wide
                        $string6 = /chromepass\.exe/ nocase ascii wide
                        $string7 = /chromepass\.zip/ nocase ascii wide
                        $string8 = "Load the passwords from another Windows user or external drive" nocase ascii wide
                        $string9 = "Load the passwords of the current logged-on user" nocase ascii wide

    condition:
        any of them
}