rule Powersploit
{
    meta:
        description = "Detection patterns for the tool 'Powersploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powersploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Get-VolumeShadowCopy " nocase ascii wide
                        $string2 = /New\-VolumeShadowCopy\s\-Volume\sC\:\\/ nocase ascii wide
                        $string3 = /VolumeShadowCopyTools\.ps1/ nocase ascii wide

    condition:
        any of them
}