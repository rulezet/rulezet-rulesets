rule impersonate
{
    meta:
        description = "Detection patterns for the tool 'impersonate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impersonate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sImpersonate\.exe\s/ nocase ascii wide
                        $string2 = /\simpersonate\.py\s/ nocase ascii wide
                        $string3 = /\/Impersonate\.exe/ nocase ascii wide
                        $string4 = /\/impersonate\.git/ nocase ascii wide
                        $string5 = /\/impersonate\.py/ nocase ascii wide
                        $string6 = /\\Impersonate\.exe/ nocase ascii wide
                        $string7 = /\\impersonate\.py/ nocase ascii wide
                        $string8 = /\\Impersonate\\Impersonate\.cpp/ nocase ascii wide
                        $string9 = /\\Temp\\Impersonate\.exe/ nocase ascii wide
                        $string10 = "00630066-0B43-474E-A93B-417CF1A65195" nocase ascii wide
                        $string11 = /Impersonate\.exe\sadduser\s/ nocase ascii wide
                        $string12 = /Impersonate\.exe\sexec\s/ nocase ascii wide
                        $string13 = /Impersonate\.exe\slist\s/ nocase ascii wide
                        $string14 = /Impersonate\.exe\slist/ nocase ascii wide
                        $string15 = /impersonate\-main\.zip/ nocase ascii wide
                        $string16 = "sensepost/impersonate" nocase ascii wide

    condition:
        any of them
}