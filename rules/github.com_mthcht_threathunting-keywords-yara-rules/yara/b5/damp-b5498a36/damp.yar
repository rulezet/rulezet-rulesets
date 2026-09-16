rule DAMP
{
    meta:
        description = "Detection patterns for the tool 'DAMP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DAMP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DAMP\.git/ nocase ascii wide
                        $string2 = "Add-RemoteRegBackdoor" nocase ascii wide
                        $string3 = /DAMP\-master\.zip/ nocase ascii wide
                        $string4 = "Get-RemoteCachedCredential" nocase ascii wide
                        $string5 = "Get-RemoteCachedCredential" nocase ascii wide
                        $string6 = "Get-RemoteLocalAccountHash" nocase ascii wide
                        $string7 = "Get-RemoteLocalAccountHash" nocase ascii wide
                        $string8 = "Get-RemoteMachineAccountHash" nocase ascii wide
                        $string9 = "HarmJ0y/DAMP" nocase ascii wide
                        $string10 = /powerdump\.ps1/ nocase ascii wide
                        $string11 = /RemoteHashRetrieval\.ps1/ nocase ascii wide

    condition:
        any of them
}