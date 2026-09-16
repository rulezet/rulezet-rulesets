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

    condition:
        any of them
}