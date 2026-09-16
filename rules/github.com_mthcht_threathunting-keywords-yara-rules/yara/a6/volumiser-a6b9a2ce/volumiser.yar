rule Volumiser
{
    meta:
        description = "Detection patterns for the tool 'Volumiser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Volumiser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sVolumiser\.exe\s/ nocase ascii wide
                        $string2 = "/CCob/Volumiser" nocase ascii wide
                        $string3 = /\/Volumiser\.exe/ nocase ascii wide
                        $string4 = /\/Volumiser\.git/ nocase ascii wide
                        $string5 = /\/Volumiser\-maser\.zip/ nocase ascii wide
                        $string6 = /\\Volumiser\.exe/ nocase ascii wide
                        $string7 = /\\Volumiser\.sln/ nocase ascii wide
                        $string8 = /\\Volumiser\\Program\.cs/ nocase ascii wide
                        $string9 = "0DF38AD4-60AF-4F93-9C7A-7FB7BA692017" nocase ascii wide
                        $string10 = /Volumiser\.exe\s\-\-image/ nocase ascii wide
                        $string11 = /Volumiser\\DiscUtils\.Ebs\\EbsMappedStream/ nocase ascii wide

    condition:
        any of them
}