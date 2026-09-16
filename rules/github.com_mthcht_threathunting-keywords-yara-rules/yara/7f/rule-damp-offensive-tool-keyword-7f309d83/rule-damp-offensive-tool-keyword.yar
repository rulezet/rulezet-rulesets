rule rule_DAMP_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DAMP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DAMP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DAMP_offensive_tool_keyword = /\/DAMP\.git/ nocase ascii wide
                        $string2_DAMP_offensive_tool_keyword = "Add-RemoteRegBackdoor" nocase ascii wide
                        $string3_DAMP_offensive_tool_keyword = /DAMP\-master\.zip/ nocase ascii wide
                        $string4_DAMP_offensive_tool_keyword = "Get-RemoteCachedCredential" nocase ascii wide
                        $string5_DAMP_offensive_tool_keyword = "Get-RemoteCachedCredential" nocase ascii wide
                        $string6_DAMP_offensive_tool_keyword = "Get-RemoteLocalAccountHash" nocase ascii wide
                        $string7_DAMP_offensive_tool_keyword = "Get-RemoteLocalAccountHash" nocase ascii wide
                        $string8_DAMP_offensive_tool_keyword = "Get-RemoteMachineAccountHash" nocase ascii wide
                        $string9_DAMP_offensive_tool_keyword = "HarmJ0y/DAMP" nocase ascii wide
                        $string10_DAMP_offensive_tool_keyword = /powerdump\.ps1/ nocase ascii wide
                        $string11_DAMP_offensive_tool_keyword = /RemoteHashRetrieval\.ps1/ nocase ascii wide

    condition:
        any of them
}