rule PwDump8
{
    meta:
        description = "Detection patterns for the tool 'PwDump8' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PwDump8"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/pwdump8\./ nocase ascii wide
                        $string2 = /\\pwdump8/ nocase ascii wide
                        $string3 = "eb046b68a014aded4f81bb952edadd283a0cd5a36fc416b89d391df3daaa6d9e" nocase ascii wide
                        $string4 = "pwdump -f " nocase ascii wide
                        $string5 = /PwDump\sv8\.2\s\-\sdumps\swindows\spassword\shashes/ nocase ascii wide

    condition:
        any of them
}