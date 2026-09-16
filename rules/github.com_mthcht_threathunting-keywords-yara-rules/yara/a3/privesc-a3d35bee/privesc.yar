rule Privesc
{
    meta:
        description = "Detection patterns for the tool 'Privesc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Privesc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sprivesc\.ps1/ nocase ascii wide
                        $string2 = /\/Privesc\.git/ nocase ascii wide
                        $string3 = /\/privesc\.ps1/ nocase ascii wide
                        $string4 = /\\privesc\.ps1/ nocase ascii wide
                        $string5 = /\\Privesc\-master/ nocase ascii wide
                        $string6 = "enjoiz/Privesc" nocase ascii wide
                        $string7 = "Invoke-Privesc" nocase ascii wide

    condition:
        any of them
}