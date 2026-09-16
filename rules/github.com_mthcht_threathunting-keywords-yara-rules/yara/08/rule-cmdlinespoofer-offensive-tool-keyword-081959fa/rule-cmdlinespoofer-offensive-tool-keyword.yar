rule rule_CmdLineSpoofer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CmdLineSpoofer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CmdLineSpoofer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CmdLineSpoofer_offensive_tool_keyword = /\/CmdLineSpoofer\.git/ nocase ascii wide
                        $string2_CmdLineSpoofer_offensive_tool_keyword = /\/CmdLineSpoofer\/.{0,1000}\.cs/ nocase ascii wide
                        $string3_CmdLineSpoofer_offensive_tool_keyword = /\[\!\]\sUnable\sto\sread\sPEB\saddress\!/ nocase ascii wide
                        $string4_CmdLineSpoofer_offensive_tool_keyword = /\[System\.Reflection\.Assembly\]\:\:Load\(\(Invoke\-WebRequest\s.{0,1000}\.exe.{0,1000}while\s\(\$true\)\{Start\-Sleep\s\-s\s1000\}/ nocase ascii wide
                        $string5_CmdLineSpoofer_offensive_tool_keyword = "5D03EFC2-72E9-4410-B147-0A1A5C743999" nocase ascii wide
                        $string6_CmdLineSpoofer_offensive_tool_keyword = /CmdLineSpoofer\.exe/ nocase ascii wide
                        $string7_CmdLineSpoofer_offensive_tool_keyword = /CmdLineSpoofer\.sln/ nocase ascii wide
                        $string8_CmdLineSpoofer_offensive_tool_keyword = "CmdLineSpoofer-master" nocase ascii wide
                        $string9_CmdLineSpoofer_offensive_tool_keyword = "plackyhacker/CmdLineSpoofer" nocase ascii wide
                        $string10_CmdLineSpoofer_offensive_tool_keyword = /powershell\.exe\snothing\sto\ssee\shere\!\s\:\-P/ nocase ascii wide
                        $string11_CmdLineSpoofer_offensive_tool_keyword = /Press\sa\skey\sto\send\sPoC\?/ nocase ascii wide
                        $string12_CmdLineSpoofer_offensive_tool_keyword = "string maliciousCommand =" nocase ascii wide
                        $string13_CmdLineSpoofer_offensive_tool_keyword = "WwBTAHkAcwB0AGUAbQAuAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA" nocase ascii wide

    condition:
        any of them
}