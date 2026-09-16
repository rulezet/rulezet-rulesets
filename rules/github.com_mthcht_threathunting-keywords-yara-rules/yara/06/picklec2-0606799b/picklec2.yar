rule PickleC2
{
    meta:
        description = "Detection patterns for the tool 'PickleC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PickleC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PickleC2\.git/ nocase ascii wide
                        $string2 = /\\Implants\\powershell\.ps1/ nocase ascii wide
                        $string3 = /\\PickleC2\\Core\\.{0,1000}\.py/ nocase ascii wide
                        $string4 = /\\PowerUp\.ps1/ nocase ascii wide
                        $string5 = /data\/implant\/.{0,1000}\/host\.ps1/ nocase ascii wide
                        $string6 = "Find-PathDLLHijack" nocase ascii wide
                        $string7 = "Find-ProcessDLLHijack" nocase ascii wide
                        $string8 = /http\:\/\/.{0,1000}\:.{0,1000}\/down\/.{0,1000}\/host\.ps1/ nocase ascii wide
                        $string9 = "IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAgACQAKAAoAFsAUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAFAAcgBpAG4AYwBpAHAAYQBsAF0AWwBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMASQBkAGUAbgB0AGkAdAB5AF0AOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAKAApACkALgBJAHMASQBuAFIAbwBsAGUAKABbAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBCAHUAaQBsAHQASQBuAFIAbwBsAGUAXQAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAJwApACkAIAAtACAAJAAoAEcAZQB0AC0ARABhAHQAZQApACIAIAB8ACAATwB1AHQALQBGAGkAbABlACAAQwA6AFwAVQBBAEMAQgB5AHAAYQBzAHMAVABlAHMAdAAuAHQAeAB0ACAALQBBAHAAcABlAG4AZAA=" nocase ascii wide
                        $string10 = /Implants\/powershell\.ps1/ nocase ascii wide
                        $string11 = "Invoke-EventVwrBypass" nocase ascii wide
                        $string12 = "Invoke-PrivescAudit " nocase ascii wide
                        $string13 = "Invoke-ServiceAbuse" nocase ascii wide
                        $string14 = "module powerup" nocase ascii wide
                        $string15 = "PickleC2-main" nocase ascii wide
                        $string16 = /UACBypassTest\.txt/ nocase ascii wide
                        $string17 = "Write-HijackDll" nocase ascii wide
                        $string18 = "xRET2pwn/PickleC2" nocase ascii wide

    condition:
        any of them
}