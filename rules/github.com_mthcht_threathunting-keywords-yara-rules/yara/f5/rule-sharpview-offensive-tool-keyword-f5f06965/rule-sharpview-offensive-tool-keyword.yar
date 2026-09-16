rule rule_SharpView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpView_offensive_tool_keyword = /\.exe\sGet\-DomainController\s\-Domain\s.{0,1000}\s\-Server\s.{0,1000}\s\-Credential\s/ nocase ascii wide
                        $string2_SharpView_offensive_tool_keyword = /\/PowerView\.ps1/ nocase ascii wide
                        $string3_SharpView_offensive_tool_keyword = /\/SharpView\.exe/ nocase ascii wide
                        $string4_SharpView_offensive_tool_keyword = /\/SharpView\.git/ nocase ascii wide
                        $string5_SharpView_offensive_tool_keyword = /\\SharpView\.exe/ nocase ascii wide
                        $string6_SharpView_offensive_tool_keyword = /\\SharpView\.pdb/ nocase ascii wide
                        $string7_SharpView_offensive_tool_keyword = ">SharpView<" nocase ascii wide
                        $string8_SharpView_offensive_tool_keyword = ">SharpView<" nocase ascii wide
                        $string9_SharpView_offensive_tool_keyword = "22A156EA-2623-45C7-8E50-E864D9FC44D3" nocase ascii wide
                        $string10_SharpView_offensive_tool_keyword = "Args_Invoke_Kerberoast" nocase ascii wide
                        $string11_SharpView_offensive_tool_keyword = "c0621954bd329b5cabe45e92b31053627c27fa40853beb2cce2734fa677ffd93" nocase ascii wide
                        $string12_SharpView_offensive_tool_keyword = "e42e5cf9-be25-4011-9623-8565b193a506" nocase ascii wide
                        $string13_SharpView_offensive_tool_keyword = "hackbuildrepeat/SharpView" nocase ascii wide
                        $string14_SharpView_offensive_tool_keyword = /SharpView\.exe/ nocase ascii wide
                        $string15_SharpView_offensive_tool_keyword = /SharpView\\SharpView/ nocase ascii wide
                        $string16_SharpView_offensive_tool_keyword = "SharpView-master" nocase ascii wide
                        $string17_SharpView_offensive_tool_keyword = "tevora-threat/SharpView/" nocase ascii wide
                        $string18_SharpView_offensive_tool_keyword = /using\sSharpView\.Enums/ nocase ascii wide

    condition:
        any of them
}