rule rule_Invoke_SessionHunter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SessionHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SessionHunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_SessionHunter_offensive_tool_keyword = /\/Invoke\-SessionHunter\.git/ nocase ascii wide
                        $string2_Invoke_SessionHunter_offensive_tool_keyword = /\\Public\\Document\\SessionHunter\.txt/ nocase ascii wide
                        $string3_Invoke_SessionHunter_offensive_tool_keyword = "e721518ae125d596d4f5148ac0e7cc08d8b9efd62ce6d874fd5958e92b50346a" nocase ascii wide
                        $string4_Invoke_SessionHunter_offensive_tool_keyword = "fc0ceb113a9dd259d3f8029f0304e4be3ba72376a1d55b101b87b8d9e9b3a11a" nocase ascii wide
                        $string5_Invoke_SessionHunter_offensive_tool_keyword = "Invoke-SessionHunter " nocase ascii wide
                        $string6_Invoke_SessionHunter_offensive_tool_keyword = /Invoke\-SessionHunter\.ps1/ nocase ascii wide
                        $string7_Invoke_SessionHunter_offensive_tool_keyword = "Invoke-WMIRemoting " nocase ascii wide
                        $string8_Invoke_SessionHunter_offensive_tool_keyword = "Leo4j/Invoke-SessionHunter" nocase ascii wide

    condition:
        any of them
}