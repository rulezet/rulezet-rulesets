rule SingleDose
{
    meta:
        description = "Detection patterns for the tool 'SingleDose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SingleDose"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SingleDose\.git/ nocase ascii wide
                        $string2 = /\\Payloads\\.{0,1000}\.bin/ nocase ascii wide
                        $string3 = /\\PoisonTendy\\Invokes\\/ nocase ascii wide
                        $string4 = /\\SingleDose\.csproj/ nocase ascii wide
                        $string5 = /\\SingleDose\.exe/ nocase ascii wide
                        $string6 = /\\SingleDose\.sln/ nocase ascii wide
                        $string7 = /\\SingleDose\-main\.zip/ nocase ascii wide
                        $string8 = "4D7AEF0B-5AA6-4AE5-971E-7141AA1FDAFC" nocase ascii wide
                        $string9 = "5FAC3991-D4FD-4227-B73D-BEE34EB89987" nocase ascii wide
                        $string10 = "C0E67E76-1C78-4152-9F79-FA27B4F7CCCA" nocase ascii wide
                        $string11 = /PoisonTendy\.dll/ nocase ascii wide
                        $string12 = "Wra7h/SingleDose" nocase ascii wide

    condition:
        any of them
}