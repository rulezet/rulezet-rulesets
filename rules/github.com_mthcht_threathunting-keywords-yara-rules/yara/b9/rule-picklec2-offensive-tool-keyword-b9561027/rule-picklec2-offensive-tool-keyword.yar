rule rule_PickleC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PickleC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PickleC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PickleC2_offensive_tool_keyword = /\/PickleC2\.git/ nocase ascii wide
                        $string2_PickleC2_offensive_tool_keyword = /\\Implants\\powershell\.ps1/ nocase ascii wide
                        $string3_PickleC2_offensive_tool_keyword = /\\PickleC2\\Core\\.{0,100}\.py/ nocase ascii wide
                        $string4_PickleC2_offensive_tool_keyword = /\\PowerUp\.ps1/ nocase ascii wide
                        $string5_PickleC2_offensive_tool_keyword = /data\/implant\/.{0,100}\/host\.ps1/ nocase ascii wide
                        $string6_PickleC2_offensive_tool_keyword = "Find-PathDLLHijack" nocase ascii wide
                        $string7_PickleC2_offensive_tool_keyword = "Find-ProcessDLLHijack" nocase ascii wide
                        $string8_PickleC2_offensive_tool_keyword = /http\:\/\/.{0,100}\:.{0,100}\/down\/.{0,100}\/host\.ps1/ nocase ascii wide
                        $string9_PickleC2_offensive_tool_keyword = "IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAgACQAKAAoAFsAUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAFAAcgBpAG4AYwBpAHAAYQBsAF0AWwBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMASQBkAGUAbgB0AGkAdAB5AF0AOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAKAApACkALgBJAHMASQBuAFIAbwBsAGUAKABbAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBCAHUAaQBsAHQASQBuAFIAbwBsAGUAXQAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAJwApACkAIAAtACAAJAAoAEcAZQB0AC0ARABhAHQAZQApACIAIAB8ACAATwB1AHQALQBGAGkAbABlACAAQwA6AFwAVQBBAEMAQgB5AHAAYQBzAHMAVABlAHMAdAAuAHQAeAB0ACAALQBBAHAAcABlAG4AZAA=" nocase ascii wide
                        $string10_PickleC2_offensive_tool_keyword = /Implants\/powershell\.ps1/ nocase ascii wide
                        $string11_PickleC2_offensive_tool_keyword = "Invoke-EventVwrBypass" nocase ascii wide
                        $string12_PickleC2_offensive_tool_keyword = "Invoke-PrivescAudit " nocase ascii wide
                        $string13_PickleC2_offensive_tool_keyword = "Invoke-ServiceAbuse" nocase ascii wide
                        $string14_PickleC2_offensive_tool_keyword = "module powerup" nocase ascii wide
                        $string15_PickleC2_offensive_tool_keyword = "PickleC2-main" nocase ascii wide
                        $string16_PickleC2_offensive_tool_keyword = /UACBypassTest\.txt/ nocase ascii wide
                        $string17_PickleC2_offensive_tool_keyword = "Write-HijackDll" nocase ascii wide
                        $string18_PickleC2_offensive_tool_keyword = "xRET2pwn/PickleC2" nocase ascii wide
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