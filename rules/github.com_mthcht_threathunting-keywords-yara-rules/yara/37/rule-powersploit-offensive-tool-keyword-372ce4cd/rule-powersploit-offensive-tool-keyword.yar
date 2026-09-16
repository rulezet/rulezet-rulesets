rule rule_Powersploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Powersploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powersploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Powersploit_offensive_tool_keyword = "Get-VolumeShadowCopy " nocase ascii wide
                        $string2_Powersploit_offensive_tool_keyword = /New\-VolumeShadowCopy\s\-Volume\sC\:\\/ nocase ascii wide
                        $string3_Powersploit_offensive_tool_keyword = /VolumeShadowCopyTools\.ps1/ nocase ascii wide

    condition:
        any of them
}