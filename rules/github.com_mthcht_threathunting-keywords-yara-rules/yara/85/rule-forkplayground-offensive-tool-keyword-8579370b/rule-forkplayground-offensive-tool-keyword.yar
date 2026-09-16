rule rule_ForkPlayground_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ForkPlayground' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ForkPlayground"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ForkPlayground_offensive_tool_keyword = /\sForkDump\.cpp/ nocase ascii wide
                        $string2_ForkPlayground_offensive_tool_keyword = /\sForkLib\.cpp/ nocase ascii wide
                        $string3_ForkPlayground_offensive_tool_keyword = /\/ForkDump\.cpp/ nocase ascii wide
                        $string4_ForkPlayground_offensive_tool_keyword = /\/ForkLib\.cpp/ nocase ascii wide
                        $string5_ForkPlayground_offensive_tool_keyword = /\/ForkPlayground\.git/ nocase ascii wide
                        $string6_ForkPlayground_offensive_tool_keyword = /\\ForkDump\.cpp/ nocase ascii wide
                        $string7_ForkPlayground_offensive_tool_keyword = /\\ForkDump\.exe/ nocase ascii wide
                        $string8_ForkPlayground_offensive_tool_keyword = /\\ForkDump\.vcxproj/ nocase ascii wide
                        $string9_ForkPlayground_offensive_tool_keyword = /\\ForkLib\.cpp/ nocase ascii wide
                        $string10_ForkPlayground_offensive_tool_keyword = /\\ForkLib\.vcxproj/ nocase ascii wide
                        $string11_ForkPlayground_offensive_tool_keyword = /\\ForkPlayground\.sln/ nocase ascii wide
                        $string12_ForkPlayground_offensive_tool_keyword = "18C681A2-072F-49D5-9DE6-74C979EAE08B" nocase ascii wide
                        $string13_ForkPlayground_offensive_tool_keyword = "AD495F95-007A-4DC1-9481-0689CA0547D9" nocase ascii wide
                        $string14_ForkPlayground_offensive_tool_keyword = "D4stiny/ForkPlayground" nocase ascii wide
                        $string15_ForkPlayground_offensive_tool_keyword = /ForkDump\-x64\.exe/ nocase ascii wide
                        $string16_ForkPlayground_offensive_tool_keyword = /ForkDump\-x64\.pdb/ nocase ascii wide
                        $string17_ForkPlayground_offensive_tool_keyword = /ForkDump\-x86\.exe/ nocase ascii wide
                        $string18_ForkPlayground_offensive_tool_keyword = /ForkDump\-x86\.pdb/ nocase ascii wide
                        $string19_ForkPlayground_offensive_tool_keyword = "ForkPlayground-master" nocase ascii wide

    condition:
        any of them
}