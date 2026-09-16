rule rule_PwDump8_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PwDump8' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PwDump8"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PwDump8_offensive_tool_keyword = /\/pwdump8\./ nocase ascii wide
                        $string2_PwDump8_offensive_tool_keyword = /\\pwdump8/ nocase ascii wide
                        $string3_PwDump8_offensive_tool_keyword = "eb046b68a014aded4f81bb952edadd283a0cd5a36fc416b89d391df3daaa6d9e" nocase ascii wide
                        $string4_PwDump8_offensive_tool_keyword = "pwdump -f " nocase ascii wide
                        $string5_PwDump8_offensive_tool_keyword = /PwDump\sv8\.2\s\-\sdumps\swindows\spassword\shashes/ nocase ascii wide

    condition:
        any of them
}