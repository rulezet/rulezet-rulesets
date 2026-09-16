rule rule_DocPlz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DocPlz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DocPlz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DocPlz_offensive_tool_keyword = /\sComunicationC2\.cpp/ nocase ascii wide
                        $string2_DocPlz_offensive_tool_keyword = /\/ComunicationC2\.cpp/ nocase ascii wide
                        $string3_DocPlz_offensive_tool_keyword = /\/DocPlz\.git/ nocase ascii wide
                        $string4_DocPlz_offensive_tool_keyword = /\/DocsPLZ\.cpp/ nocase ascii wide
                        $string5_DocPlz_offensive_tool_keyword = /\/DocsPLZ\.exe/ nocase ascii wide
                        $string6_DocPlz_offensive_tool_keyword = /\/ServerC2\.cpp/ nocase ascii wide
                        $string7_DocPlz_offensive_tool_keyword = /\/ServerC2\.exe/ nocase ascii wide
                        $string8_DocPlz_offensive_tool_keyword = /\\ComunicationC2\.cpp/ nocase ascii wide
                        $string9_DocPlz_offensive_tool_keyword = /\\DocsPLZ\.cpp/ nocase ascii wide
                        $string10_DocPlz_offensive_tool_keyword = /\\DocsPLZ\.exe/ nocase ascii wide
                        $string11_DocPlz_offensive_tool_keyword = /\\Persistence\.exe/ nocase ascii wide
                        $string12_DocPlz_offensive_tool_keyword = /\\ServerC2\.cpp/ nocase ascii wide
                        $string13_DocPlz_offensive_tool_keyword = /\\ServerC2\.exe/ nocase ascii wide
                        $string14_DocPlz_offensive_tool_keyword = /\\ServerC2\\ServerC2\./ nocase ascii wide
                        $string15_DocPlz_offensive_tool_keyword = "4C3B106C-8782-4374-9459-851749072123" nocase ascii wide
                        $string16_DocPlz_offensive_tool_keyword = "5E0812A9-C727-44F3-A2E3-8286CDC3ED4F" nocase ascii wide
                        $string17_DocPlz_offensive_tool_keyword = /DocPlz\-main\.zip/ nocase ascii wide
                        $string18_DocPlz_offensive_tool_keyword = /DocsPLZ\\DocsPLZ\./ nocase ascii wide
                        $string19_DocPlz_offensive_tool_keyword = "TheD1rkMtr/DocPlz" nocase ascii wide

    condition:
        any of them
}