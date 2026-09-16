rule power_pwn
{
    meta:
        description = "Detection patterns for the tool 'power-pwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "power-pwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/power\-pwn\.git/ nocase ascii wide
                        $string2 = /\\malware_runner\.py/ nocase ascii wide
                        $string3 = /\\power\-pwn\\/ nocase ascii wide
                        $string4 = /Cleanup\-57BFF48E\-24FB\-48E9\-A390\-AC62ADF38B07\.json/ nocase ascii wide
                        $string5 = /CodeExec\-D37DA402\-3829\-492F\-90D0\-8EC3909514EB\.json/ nocase ascii wide
                        $string6 = /Endpoint\-EE15B860\-9EEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
                        $string7 = /Exfil\-EC266392\-D6BC\-4F7B\-A4D1\-410166D30B55\.json/ nocase ascii wide
                        $string8 = "mbrg/power-pwn" nocase ascii wide
                        $string9 = /powerpwn\.powerdump/ nocase ascii wide
                        $string10 = "powerpwn_tests" nocase ascii wide
                        $string11 = "power-pwn-main" nocase ascii wide
                        $string12 = /Ransomware\-E20F7CED\-42AD\-485E\-BE4D\-DE21DCE58EC0\.json/ nocase ascii wide
                        $string13 = /RunCleanup\-77740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
                        $string14 = /RunCodeExec\-75740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
                        $string15 = /RunExfil\-78740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
                        $string16 = /RunRansomware\-76740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
                        $string17 = /RunStealCookie\-8B5C57DA\-F404\-ED11\-82E4\-0022481BF843\.json/ nocase ascii wide
                        $string18 = /RunStealPowerAutomateToken\-8C5C57DA\-F404\-ED11\-82E4\-0022481BF843\.json/ nocase ascii wide
                        $string19 = /StealCookie\-28050355\-D9DF\-4CE7\-BFBC\-4F7DDE890C2A\.json/ nocase ascii wide
                        $string20 = /StealPowerAutomateToken\-C4E7B7DA\-54E4\-49AB\-B634\-FCCD77C65025\.json/ nocase ascii wide

    condition:
        any of them
}