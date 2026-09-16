rule SharpKiller
{
    meta:
        description = "Detection patterns for the tool 'SharpKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpKiller"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpKiller\.git/ nocase ascii wide
                        $string2 = /\/Sharp\-Killer\.sln/ nocase ascii wide
                        $string3 = /\\AMSIPatcher\.cs/ nocase ascii wide
                        $string4 = /\\Sharp\-Killer\.sln/ nocase ascii wide
                        $string5 = "4DD3206C-F14A-43A3-8EA8-88676810B8CD" nocase ascii wide
                        $string6 = "S1lkys/SharpKiller" nocase ascii wide
                        $string7 = /Sharp\-Killer\.csproj/ nocase ascii wide
                        $string8 = /Sharp\-Killer\.exe/ nocase ascii wide
                        $string9 = /Sharp\-Killer\.pdb/ nocase ascii wide
                        $string10 = "SharpKiller-main" nocase ascii wide

    condition:
        any of them
}