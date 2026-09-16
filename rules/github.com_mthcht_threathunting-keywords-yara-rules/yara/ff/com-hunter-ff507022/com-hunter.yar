rule COM_Hunter
{
    meta:
        description = "Detection patterns for the tool 'COM-Hunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "COM-Hunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPersist\sGeneral\s.{0,1000}\.dll/ nocase ascii wide
                        $string2 = /\sPersist\sTasksch\s.{0,1000}\.dll/ nocase ascii wide
                        $string3 = /\sPersist\sTreatAs\s.{0,1000}\.dll/ nocase ascii wide
                        $string4 = /\.exe\sSearch\sFind\-Persist/ nocase ascii wide
                        $string5 = /\/COM\-Hunter\.csproj/ nocase ascii wide
                        $string6 = /\/COM\-Hunter\.exe/ nocase ascii wide
                        $string7 = /\/COM\-Hunter\.git/ nocase ascii wide
                        $string8 = /\/COM\-Hunter\.sln/ nocase ascii wide
                        $string9 = /\\COM\-Hunter\.csproj/ nocase ascii wide
                        $string10 = /\\COM\-Hunter\.exe/ nocase ascii wide
                        $string11 = /\\COM\-Hunter\.sln/ nocase ascii wide
                        $string12 = "09323E4D-BE0F-452A-9CA8-B07D2CFA9804" nocase ascii wide
                        $string13 = /COM\-Hunter_v.{0,1000}\.zip/ nocase ascii wide
                        $string14 = "COM-Hunter-main" nocase ascii wide
                        $string15 = "nickvourd/COM-Hunter" nocase ascii wide

    condition:
        any of them
}