rule rule_Shell3er_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Shell3er' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shell3er"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Shell3er_offensive_tool_keyword = /\sShell3er\.ps1/ nocase ascii wide
                        $string2_Shell3er_offensive_tool_keyword = /\/Shell3er\.git/ nocase ascii wide
                        $string3_Shell3er_offensive_tool_keyword = /\/Shell3er\.ps1/ nocase ascii wide
                        $string4_Shell3er_offensive_tool_keyword = "/Shell3er/" nocase ascii wide
                        $string5_Shell3er_offensive_tool_keyword = /\\Shell3er\.ps1/ nocase ascii wide
                        $string6_Shell3er_offensive_tool_keyword = /\\Shell3er\-main/ nocase ascii wide
                        $string7_Shell3er_offensive_tool_keyword = "6334665cbd227e91e2fe4517cc5bb0e6f4163aa4ae10430e034df836287dc339" nocase ascii wide
                        $string8_Shell3er_offensive_tool_keyword = "cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACAALQBGAGkAbABlACAAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAUwBoAGUAbABsADMAZQByAC4AcABzADEA" nocase ascii wide
                        $string9_Shell3er_offensive_tool_keyword = "cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACAALQBGAGkAbABlACAAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAUwBoAGUAbABsADMAZQByAC4AcABzADEA" nocase ascii wide
                        $string10_Shell3er_offensive_tool_keyword = "nc -nlvp 4444" nocase ascii wide
                        $string11_Shell3er_offensive_tool_keyword = "SABLAEMAVQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAUgB1AG4A" nocase ascii wide
                        $string12_Shell3er_offensive_tool_keyword = /Shell3er\.ps1/ nocase ascii wide
                        $string13_Shell3er_offensive_tool_keyword = "Welcome to the Mrvar0x PowerShell Remote Shell!" nocase ascii wide
                        $string14_Shell3er_offensive_tool_keyword = "yehia-mamdouh/Shell3er" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}