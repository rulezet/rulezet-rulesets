rule rule_SingleDose_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SingleDose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SingleDose"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SingleDose_offensive_tool_keyword = /\/SingleDose\.git/ nocase ascii wide
                        $string2_SingleDose_offensive_tool_keyword = /\\Payloads\\.{0,1000}\.bin/ nocase ascii wide
                        $string3_SingleDose_offensive_tool_keyword = /\\PoisonTendy\\Invokes\\/ nocase ascii wide
                        $string4_SingleDose_offensive_tool_keyword = /\\SingleDose\.csproj/ nocase ascii wide
                        $string5_SingleDose_offensive_tool_keyword = /\\SingleDose\.exe/ nocase ascii wide
                        $string6_SingleDose_offensive_tool_keyword = /\\SingleDose\.sln/ nocase ascii wide
                        $string7_SingleDose_offensive_tool_keyword = /\\SingleDose\-main\.zip/ nocase ascii wide
                        $string8_SingleDose_offensive_tool_keyword = "4D7AEF0B-5AA6-4AE5-971E-7141AA1FDAFC" nocase ascii wide
                        $string9_SingleDose_offensive_tool_keyword = "5FAC3991-D4FD-4227-B73D-BEE34EB89987" nocase ascii wide
                        $string10_SingleDose_offensive_tool_keyword = "C0E67E76-1C78-4152-9F79-FA27B4F7CCCA" nocase ascii wide
                        $string11_SingleDose_offensive_tool_keyword = /PoisonTendy\.dll/ nocase ascii wide
                        $string12_SingleDose_offensive_tool_keyword = "Wra7h/SingleDose" nocase ascii wide

    condition:
        any of them
}