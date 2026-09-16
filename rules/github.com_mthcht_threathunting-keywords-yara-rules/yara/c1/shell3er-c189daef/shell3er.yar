rule Shell3er
{
    meta:
        description = "Detection patterns for the tool 'Shell3er' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shell3er"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sShell3er\.ps1/ nocase ascii wide
                        $string2 = /\/Shell3er\.git/ nocase ascii wide
                        $string3 = /\/Shell3er\.ps1/ nocase ascii wide
                        $string4 = "/Shell3er/" nocase ascii wide
                        $string5 = /\\Shell3er\.ps1/ nocase ascii wide
                        $string6 = /\\Shell3er\-main/ nocase ascii wide
                        $string7 = "6334665cbd227e91e2fe4517cc5bb0e6f4163aa4ae10430e034df836287dc339" nocase ascii wide
                        $string8 = "cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACAALQBGAGkAbABlACAAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAUwBoAGUAbABsADMAZQByAC4AcABzADEA" nocase ascii wide
                        $string9 = "cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACAALQBGAGkAbABlACAAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAUwBoAGUAbABsADMAZQByAC4AcABzADEA" nocase ascii wide
                        $string10 = "nc -nlvp 4444" nocase ascii wide
                        $string11 = "SABLAEMAVQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAUgB1AG4A" nocase ascii wide
                        $string12 = /Shell3er\.ps1/ nocase ascii wide
                        $string13 = "Welcome to the Mrvar0x PowerShell Remote Shell!" nocase ascii wide
                        $string14 = "yehia-mamdouh/Shell3er" nocase ascii wide

    condition:
        any of them
}