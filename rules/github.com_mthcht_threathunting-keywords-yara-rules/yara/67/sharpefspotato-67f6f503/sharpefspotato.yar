rule SharpEfsPotato
{
    meta:
        description = "Detection patterns for the tool 'SharpEfsPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEfsPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sC\:\\temp\\w\.log/ nocase ascii wide
                        $string2 = " SharpEfsPotato" nocase ascii wide
                        $string3 = "/SharpEfsPotato" nocase ascii wide
                        $string4 = /\[\+\]\sServer\sconnected\sto\sour\sevil\sRPC\spipe/ nocase ascii wide
                        $string5 = /\[\+\]\sTriggering\sname\spipe\saccess\son\sevil\sPIPE/ nocase ascii wide
                        $string6 = /\\SharpEfsPotato/ nocase ascii wide
                        $string7 = /\\SharpEfsPotato\.pdb/ nocase ascii wide
                        $string8 = ">SharpEfsPotato<" nocase ascii wide
                        $string9 = "AAB4D641-C310-4572-A9C2-6D12593AB28E" nocase ascii wide
                        $string10 = "SharpEfsPotato by @bugch3ck" nocase ascii wide
                        $string11 = "SharpEfsPotato by @bugch3ck" nocase ascii wide
                        $string12 = /SharpEfsPotato\.cs/ nocase ascii wide
                        $string13 = /SharpEfsPotato\.exe/ nocase ascii wide
                        $string14 = /SharpEfsPotato\.exe/ nocase ascii wide
                        $string15 = /SharpEfsPotato\.sln/ nocase ascii wide
                        $string16 = "SharpEfsPotato-master" nocase ascii wide

    condition:
        any of them
}