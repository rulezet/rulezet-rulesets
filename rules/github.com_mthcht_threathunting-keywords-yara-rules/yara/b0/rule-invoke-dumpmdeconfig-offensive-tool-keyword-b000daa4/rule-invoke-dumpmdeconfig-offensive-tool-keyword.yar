rule rule_Invoke_DumpMDEConfig_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-DumpMDEConfig' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-DumpMDEConfig"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_DumpMDEConfig_offensive_tool_keyword = /\[\+\]\sDefender\sConfig\sDumped\sto\s/ nocase ascii wide
                        $string2_Invoke_DumpMDEConfig_offensive_tool_keyword = /\[\+\]\sDumped\sAllowed\sThreats\sto\s.{0,1000}\s/ nocase ascii wide
                        $string3_Invoke_DumpMDEConfig_offensive_tool_keyword = /\[\+\]\sDumped\sExclusion\sPaths\sto\sExclusionPaths\.csv/ nocase ascii wide
                        $string4_Invoke_DumpMDEConfig_offensive_tool_keyword = /\[\+\]\sDumped\sExploit\sGuard\sProtection\sHistory/ nocase ascii wide
                        $string5_Invoke_DumpMDEConfig_offensive_tool_keyword = /\[\+\]\sDumped\sFirewall\sExclusions\sto\s/ nocase ascii wide
                        $string6_Invoke_DumpMDEConfig_offensive_tool_keyword = /\[\+\]\sDumped\sProtection\sHistory\sto\sProtectionHistory\.csv/ nocase ascii wide
                        $string7_Invoke_DumpMDEConfig_offensive_tool_keyword = /\[\+\]\sDumping\sDefender\sExcluded\sPaths/ nocase ascii wide
                        $string8_Invoke_DumpMDEConfig_offensive_tool_keyword = /\[\+\]\sDumping\sDefender\sProtection\sHistory/ nocase ascii wide
                        $string9_Invoke_DumpMDEConfig_offensive_tool_keyword = /\[\+\]\sDumping\sEnabled\sASR\sRules/ nocase ascii wide
                        $string10_Invoke_DumpMDEConfig_offensive_tool_keyword = /\[System\[Provider\[\@Name\=\'Microsoft\-Windows\-Windows\sDefender\'\]\sand\s\(EventID\=5007\)\]\]/ nocase ascii wide
                        $string11_Invoke_DumpMDEConfig_offensive_tool_keyword = /\\ExploitGuardProtectionHistory\.csv/ nocase ascii wide
                        $string12_Invoke_DumpMDEConfig_offensive_tool_keyword = "78a098cf3b91a354d6425bb5c08af4a0cc137a71bec4ad44707d864e263a4384" nocase ascii wide
                        $string13_Invoke_DumpMDEConfig_offensive_tool_keyword = "Invoke-DumpMDEConfig" nocase ascii wide
                        $string14_Invoke_DumpMDEConfig_offensive_tool_keyword = "Query-ExploitGuardProtectionHistory " nocase ascii wide

    condition:
        any of them
}