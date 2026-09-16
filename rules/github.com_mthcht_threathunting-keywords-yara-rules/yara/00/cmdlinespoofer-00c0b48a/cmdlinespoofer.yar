rule CmdLineSpoofer
{
    meta:
        description = "Detection patterns for the tool 'CmdLineSpoofer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CmdLineSpoofer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/CmdLineSpoofer\.git/ nocase ascii wide
                        $string2 = /\/CmdLineSpoofer\/.{0,1000}\.cs/ nocase ascii wide
                        $string3 = /\[\!\]\sUnable\sto\sread\sPEB\saddress\!/ nocase ascii wide
                        $string4 = /\[System\.Reflection\.Assembly\]\:\:Load\(\(Invoke\-WebRequest\s.{0,1000}\.exe.{0,1000}while\s\(\$true\)\{Start\-Sleep\s\-s\s1000\}/ nocase ascii wide
                        $string5 = "5D03EFC2-72E9-4410-B147-0A1A5C743999" nocase ascii wide
                        $string6 = /CmdLineSpoofer\.exe/ nocase ascii wide
                        $string7 = /CmdLineSpoofer\.sln/ nocase ascii wide
                        $string8 = "CmdLineSpoofer-master" nocase ascii wide
                        $string9 = "plackyhacker/CmdLineSpoofer" nocase ascii wide
                        $string10 = /powershell\.exe\snothing\sto\ssee\shere\!\s\:\-P/ nocase ascii wide
                        $string11 = /Press\sa\skey\sto\send\sPoC\?/ nocase ascii wide
                        $string12 = "string maliciousCommand =" nocase ascii wide
                        $string13 = "WwBTAHkAcwB0AGUAbQAuAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA" nocase ascii wide

    condition:
        any of them
}