rule rule_Invoke_ShareHunter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ShareHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ShareHunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_ShareHunter_offensive_tool_keyword = /\\Shares_CleanupCommand\.txt/ nocase ascii wide
                        $string2_Invoke_ShareHunter_offensive_tool_keyword = /\\Shares_Readable\.txt/ nocase ascii wide
                        $string3_Invoke_ShareHunter_offensive_tool_keyword = /\\Shares_Writable\.txt\\"/ nocase ascii wide
                        $string4_Invoke_ShareHunter_offensive_tool_keyword = "Invoke-ShareHunter " nocase ascii wide
                        $string5_Invoke_ShareHunter_offensive_tool_keyword = /Invoke\-ShareHunter\.ps1/ nocase ascii wide
                        $string6_Invoke_ShareHunter_offensive_tool_keyword = /Invoke\-URLFileClean\s\-WritableShares\s.{0,1000}\s\-URLAttackFileName/ nocase ascii wide

    condition:
        any of them
}