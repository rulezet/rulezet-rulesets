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
                        $string3_PickleC2_offensive_tool_keyword = /\\PickleC2\\Core\\.{0,1000}\.py/ nocase ascii wide
                        $string4_PickleC2_offensive_tool_keyword = /\\PowerUp\.ps1/ nocase ascii wide
                        $string5_PickleC2_offensive_tool_keyword = /data\/implant\/.{0,1000}\/host\.ps1/ nocase ascii wide
                        $string6_PickleC2_offensive_tool_keyword = "Find-PathDLLHijack" nocase ascii wide
                        $string7_PickleC2_offensive_tool_keyword = "Find-ProcessDLLHijack" nocase ascii wide
                        $string8_PickleC2_offensive_tool_keyword = /http\:\/\/.{0,1000}\:.{0,1000}\/down\/.{0,1000}\/host\.ps1/ nocase ascii wide
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

    condition:
        any of them
}