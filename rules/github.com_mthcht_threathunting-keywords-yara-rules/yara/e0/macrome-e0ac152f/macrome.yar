rule Macrome
{
    meta:
        description = "Detection patterns for the tool 'Macrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Macrome"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sCharSubroutine\-Macro\.xls/ nocase ascii wide
                        $string2 = /\spopcalc\.bin\s/ nocase ascii wide
                        $string3 = /\spopcalc64\.bin\s/ nocase ascii wide
                        $string4 = /\/BaseNEncoder\.cs/ nocase ascii wide
                        $string5 = /\/BIFFRecordEncryption\.cs/ nocase ascii wide
                        $string6 = /\/ExcelDocWriter\.cs/ nocase ascii wide
                        $string7 = /\/MacroPatterns\.cs/ nocase ascii wide
                        $string8 = "/michaelweber/Macrome" nocase ascii wide
                        $string9 = /\/RC4BinaryEncryption\.cs/ nocase ascii wide
                        $string10 = /\/XorObfuscation\.cs/ nocase ascii wide
                        $string11 = /b2xtranslator\.xls\.csproj/ nocase ascii wide
                        $string12 = /decoy_document\.xls/ nocase ascii wide
                        $string13 = /Macrome\s.{0,1000}\-\-decoy\-document/ nocase ascii wide
                        $string14 = /Macrome\s.{0,1000}\-\-payload/ nocase ascii wide
                        $string15 = "Macrome build" nocase ascii wide
                        $string16 = /Macrome\.csproj/ nocase ascii wide
                        $string17 = /Macrome\.dll/ nocase ascii wide
                        $string18 = /Macrome\.sln/ nocase ascii wide
                        $string19 = /\-\-path\sdocToDump\.xls/ nocase ascii wide
                        $string20 = "--payload-type Macro" nocase ascii wide
                        $string21 = /ReadyToPhish\.xls/ nocase ascii wide

    condition:
        any of them
}