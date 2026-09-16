rule Invoke_ShareHunter
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ShareHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ShareHunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\Shares_CleanupCommand\.txt/ nocase ascii wide
                        $string2 = /\\Shares_Readable\.txt/ nocase ascii wide
                        $string3 = /\\Shares_Writable\.txt\\"/ nocase ascii wide
                        $string4 = "Invoke-ShareHunter " nocase ascii wide
                        $string5 = /Invoke\-ShareHunter\.ps1/ nocase ascii wide
                        $string6 = /Invoke\-URLFileClean\s\-WritableShares\s.{0,1000}\s\-URLAttackFileName/ nocase ascii wide

    condition:
        any of them
}