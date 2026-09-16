rule rule_power_pwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'power-pwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "power-pwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_power_pwn_offensive_tool_keyword = /\/power\-pwn\.git/ nocase ascii wide
                        $string2_power_pwn_offensive_tool_keyword = /\\malware_runner\.py/ nocase ascii wide
                        $string3_power_pwn_offensive_tool_keyword = /\\power\-pwn\\/ nocase ascii wide
                        $string4_power_pwn_offensive_tool_keyword = /Cleanup\-57BFF48E\-24FB\-48E9\-A390\-AC62ADF38B07\.json/ nocase ascii wide
                        $string5_power_pwn_offensive_tool_keyword = /CodeExec\-D37DA402\-3829\-492F\-90D0\-8EC3909514EB\.json/ nocase ascii wide
                        $string6_power_pwn_offensive_tool_keyword = /Endpoint\-EE15B860\-9EEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
                        $string7_power_pwn_offensive_tool_keyword = /Exfil\-EC266392\-D6BC\-4F7B\-A4D1\-410166D30B55\.json/ nocase ascii wide
                        $string8_power_pwn_offensive_tool_keyword = "mbrg/power-pwn" nocase ascii wide
                        $string9_power_pwn_offensive_tool_keyword = /powerpwn\.powerdump/ nocase ascii wide
                        $string10_power_pwn_offensive_tool_keyword = "powerpwn_tests" nocase ascii wide
                        $string11_power_pwn_offensive_tool_keyword = "power-pwn-main" nocase ascii wide
                        $string12_power_pwn_offensive_tool_keyword = /Ransomware\-E20F7CED\-42AD\-485E\-BE4D\-DE21DCE58EC0\.json/ nocase ascii wide
                        $string13_power_pwn_offensive_tool_keyword = /RunCleanup\-77740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
                        $string14_power_pwn_offensive_tool_keyword = /RunCodeExec\-75740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
                        $string15_power_pwn_offensive_tool_keyword = /RunExfil\-78740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
                        $string16_power_pwn_offensive_tool_keyword = /RunRansomware\-76740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
                        $string17_power_pwn_offensive_tool_keyword = /RunStealCookie\-8B5C57DA\-F404\-ED11\-82E4\-0022481BF843\.json/ nocase ascii wide
                        $string18_power_pwn_offensive_tool_keyword = /RunStealPowerAutomateToken\-8C5C57DA\-F404\-ED11\-82E4\-0022481BF843\.json/ nocase ascii wide
                        $string19_power_pwn_offensive_tool_keyword = /StealCookie\-28050355\-D9DF\-4CE7\-BFBC\-4F7DDE890C2A\.json/ nocase ascii wide
                        $string20_power_pwn_offensive_tool_keyword = /StealPowerAutomateToken\-C4E7B7DA\-54E4\-49AB\-B634\-FCCD77C65025\.json/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}