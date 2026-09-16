rule rule_SharpEfsPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpEfsPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEfsPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpEfsPotato_offensive_tool_keyword = /\sC\:\\temp\\w\.log/ nocase ascii wide
                        $string2_SharpEfsPotato_offensive_tool_keyword = " SharpEfsPotato" nocase ascii wide
                        $string3_SharpEfsPotato_offensive_tool_keyword = "/SharpEfsPotato" nocase ascii wide
                        $string4_SharpEfsPotato_offensive_tool_keyword = /\[\+\]\sServer\sconnected\sto\sour\sevil\sRPC\spipe/ nocase ascii wide
                        $string5_SharpEfsPotato_offensive_tool_keyword = /\[\+\]\sTriggering\sname\spipe\saccess\son\sevil\sPIPE/ nocase ascii wide
                        $string6_SharpEfsPotato_offensive_tool_keyword = /\\SharpEfsPotato/ nocase ascii wide
                        $string7_SharpEfsPotato_offensive_tool_keyword = /\\SharpEfsPotato\.pdb/ nocase ascii wide
                        $string8_SharpEfsPotato_offensive_tool_keyword = ">SharpEfsPotato<" nocase ascii wide
                        $string9_SharpEfsPotato_offensive_tool_keyword = "AAB4D641-C310-4572-A9C2-6D12593AB28E" nocase ascii wide
                        $string10_SharpEfsPotato_offensive_tool_keyword = "SharpEfsPotato by @bugch3ck" nocase ascii wide
                        $string11_SharpEfsPotato_offensive_tool_keyword = "SharpEfsPotato by @bugch3ck" nocase ascii wide
                        $string12_SharpEfsPotato_offensive_tool_keyword = /SharpEfsPotato\.cs/ nocase ascii wide
                        $string13_SharpEfsPotato_offensive_tool_keyword = /SharpEfsPotato\.exe/ nocase ascii wide
                        $string14_SharpEfsPotato_offensive_tool_keyword = /SharpEfsPotato\.exe/ nocase ascii wide
                        $string15_SharpEfsPotato_offensive_tool_keyword = /SharpEfsPotato\.sln/ nocase ascii wide
                        $string16_SharpEfsPotato_offensive_tool_keyword = "SharpEfsPotato-master" nocase ascii wide

    condition:
        any of them
}