rule PS2EXE
{
    meta:
        description = "Detection patterns for the tool 'PS2EXE' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PS2EXE"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPS2EXE\.ps1/ nocase ascii wide
                        $string2 = /\/PS2EXE\.git/ nocase ascii wide
                        $string3 = /\/PS2EXE\.ps1/ nocase ascii wide
                        $string4 = "/PS2EXE/" nocase ascii wide
                        $string5 = /\\PS2EXE\.ps1/ nocase ascii wide
                        $string6 = /\\Win\-PS2EXE/ nocase ascii wide
                        $string7 = "760c4649c5acd734d931ee64ebfc62eb19fa5c45137f4712b84aba7a356cda91" nocase ascii wide
                        $string8 = "Install-Module ps2exe" nocase ascii wide
                        $string9 = "Invoke-ps2exe" nocase ascii wide
                        $string10 = "Leo4j/PS2EXE" nocase ascii wide
                        $string11 = "MScholtes/PS2EXE" nocase ascii wide
                        $string12 = /ps\.AddScript\(Encoding\.UTF8\.GetString\(Convert\.FromBase64String\(script\)/ nocase ascii wide
                        $string13 = /PS1ToEXE.{0,1000}PS2EXE\.ps1/ nocase ascii wide
                        $string14 = "ps2exe -" nocase ascii wide
                        $string15 = /ps2exe\s.{0,1000}\.ps1.{0,1000}\.exe/ nocase ascii wide
                        $string16 = /PS2EXE\s\-content\s\$.{0,1000}\s\-outputFile\s/ nocase ascii wide
                        $string17 = /ps2exe\.ps1/ nocase ascii wide
                        $string18 = /ps2exe\.psd1/ nocase ascii wide
                        $string19 = /ps2exe\.psm1/ nocase ascii wide
                        $string20 = "PS2EXE-master" nocase ascii wide
                        $string21 = /Win\-PS2EXE\.exe/ nocase ascii wide

    condition:
        any of them
}