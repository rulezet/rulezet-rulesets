rule rule_COM_Hunter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'COM-Hunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "COM-Hunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_COM_Hunter_offensive_tool_keyword = /\sPersist\sGeneral\s.{0,1000}\.dll/ nocase ascii wide
                        $string2_COM_Hunter_offensive_tool_keyword = /\sPersist\sTasksch\s.{0,1000}\.dll/ nocase ascii wide
                        $string3_COM_Hunter_offensive_tool_keyword = /\sPersist\sTreatAs\s.{0,1000}\.dll/ nocase ascii wide
                        $string4_COM_Hunter_offensive_tool_keyword = /\.exe\sSearch\sFind\-Persist/ nocase ascii wide
                        $string5_COM_Hunter_offensive_tool_keyword = /\/COM\-Hunter\.csproj/ nocase ascii wide
                        $string6_COM_Hunter_offensive_tool_keyword = /\/COM\-Hunter\.exe/ nocase ascii wide
                        $string7_COM_Hunter_offensive_tool_keyword = /\/COM\-Hunter\.git/ nocase ascii wide
                        $string8_COM_Hunter_offensive_tool_keyword = /\/COM\-Hunter\.sln/ nocase ascii wide
                        $string9_COM_Hunter_offensive_tool_keyword = /\\COM\-Hunter\.csproj/ nocase ascii wide
                        $string10_COM_Hunter_offensive_tool_keyword = /\\COM\-Hunter\.exe/ nocase ascii wide
                        $string11_COM_Hunter_offensive_tool_keyword = /\\COM\-Hunter\.sln/ nocase ascii wide
                        $string12_COM_Hunter_offensive_tool_keyword = "09323E4D-BE0F-452A-9CA8-B07D2CFA9804" nocase ascii wide
                        $string13_COM_Hunter_offensive_tool_keyword = /COM\-Hunter_v.{0,1000}\.zip/ nocase ascii wide
                        $string14_COM_Hunter_offensive_tool_keyword = "COM-Hunter-main" nocase ascii wide
                        $string15_COM_Hunter_offensive_tool_keyword = "nickvourd/COM-Hunter" nocase ascii wide

    condition:
        any of them
}