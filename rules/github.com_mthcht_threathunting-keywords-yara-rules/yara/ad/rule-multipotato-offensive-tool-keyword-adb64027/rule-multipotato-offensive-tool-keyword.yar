rule rule_MultiPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MultiPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MultiPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MultiPotato_offensive_tool_keyword = /\s\-t\sBindShell\s\-p\s.{0,1000}pwned\\pipe\\spoolss/ nocase ascii wide
                        $string2_MultiPotato_offensive_tool_keyword = /\s\-t\sCreateProcessAsUserW\s\-p\s.{0,1000}pwned\\pipe\\spoolss.{0,1000}\s\-e\s.{0,1000}\.exe/ nocase ascii wide
                        $string3_MultiPotato_offensive_tool_keyword = /\/MultiPotato\.git/ nocase ascii wide
                        $string4_MultiPotato_offensive_tool_keyword = /\\\\\.\\pipe\\pwned\/pipe\/srvsvc/ nocase ascii wide
                        $string5_MultiPotato_offensive_tool_keyword = "61CE6716-E619-483C-B535-8694F7617548" nocase ascii wide
                        $string6_MultiPotato_offensive_tool_keyword = "localhost/pipe/pwned" nocase ascii wide
                        $string7_MultiPotato_offensive_tool_keyword = /MS\-RPRN\.exe\s\\\\.{0,1000}\s\\\\.{0,1000}\/pipe\/pwned/ nocase ascii wide
                        $string8_MultiPotato_offensive_tool_keyword = /MultiPotato\.cpp/ nocase ascii wide
                        $string9_MultiPotato_offensive_tool_keyword = /MultiPotato\.exe/ nocase ascii wide
                        $string10_MultiPotato_offensive_tool_keyword = "MultiPotato-main" nocase ascii wide
                        $string11_MultiPotato_offensive_tool_keyword = /PetitPotamModified\.exe/ nocase ascii wide
                        $string12_MultiPotato_offensive_tool_keyword = "S3cretP4ssw0rd!" nocase ascii wide
                        $string13_MultiPotato_offensive_tool_keyword = "S3cur3Th1sSh1t/MultiPotato" nocase ascii wide
                        $string14_MultiPotato_offensive_tool_keyword = /TokenKidnapping\.cpp/ nocase ascii wide
                        $string15_MultiPotato_offensive_tool_keyword = /TokenKidnapping\.exe/ nocase ascii wide

    condition:
        any of them
}