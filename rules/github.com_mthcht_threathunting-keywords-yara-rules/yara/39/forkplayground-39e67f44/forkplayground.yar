rule ForkPlayground
{
    meta:
        description = "Detection patterns for the tool 'ForkPlayground' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ForkPlayground"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sForkDump\.cpp/ nocase ascii wide
                        $string2 = /\sForkLib\.cpp/ nocase ascii wide
                        $string3 = /\/ForkDump\.cpp/ nocase ascii wide
                        $string4 = /\/ForkLib\.cpp/ nocase ascii wide
                        $string5 = /\/ForkPlayground\.git/ nocase ascii wide
                        $string6 = /\\ForkDump\.cpp/ nocase ascii wide
                        $string7 = /\\ForkDump\.exe/ nocase ascii wide
                        $string8 = /\\ForkDump\.vcxproj/ nocase ascii wide
                        $string9 = /\\ForkLib\.cpp/ nocase ascii wide
                        $string10 = /\\ForkLib\.vcxproj/ nocase ascii wide
                        $string11 = /\\ForkPlayground\.sln/ nocase ascii wide
                        $string12 = "18C681A2-072F-49D5-9DE6-74C979EAE08B" nocase ascii wide
                        $string13 = "AD495F95-007A-4DC1-9481-0689CA0547D9" nocase ascii wide
                        $string14 = "D4stiny/ForkPlayground" nocase ascii wide
                        $string15 = /ForkDump\-x64\.exe/ nocase ascii wide
                        $string16 = /ForkDump\-x64\.pdb/ nocase ascii wide
                        $string17 = /ForkDump\-x86\.exe/ nocase ascii wide
                        $string18 = /ForkDump\-x86\.pdb/ nocase ascii wide
                        $string19 = "ForkPlayground-master" nocase ascii wide

    condition:
        any of them
}