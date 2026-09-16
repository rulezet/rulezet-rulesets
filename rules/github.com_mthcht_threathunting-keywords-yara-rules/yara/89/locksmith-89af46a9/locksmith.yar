rule Locksmith
{
    meta:
        description = "Detection patterns for the tool 'Locksmith' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Locksmith"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-InputPath\s\.\\TrustedForests\.txt/ nocase ascii wide
                        $string2 = /\/Locksmith\.git/ nocase ascii wide
                        $string3 = /Invoke\-Locksmith\.ps1/ nocase ascii wide
                        $string4 = /Locksmith\-main\.zip/ nocase ascii wide

    condition:
        any of them
}