rule Spartacus
{
    meta:
        description = "Detection patterns for the tool 'Spartacus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spartacus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-action\sexports\s\-\-dll\sC\:\\Windows\\System32\\amsi\.dll/ nocase ascii wide
                        $string2 = /\s\-\-dll\s.{0,1000}\s\-\-only\s.{0,1000}AmsiScanBuffer.{0,1000}AmsiScanString/ nocase ascii wide
                        $string3 = /\s\-\-dll\sC\:\\Windows\\System32\\version\.dll.{0,1000}\-\-dll\sC\:\\Windows\\System32\\userenv\.dll/ nocase ascii wide
                        $string4 = /\s\-\-mode\sproxy\s\-\-ghidra\s.{0,1000}\-\-dll\s/ nocase ascii wide
                        $string5 = /\\tmp\\dll\-collection/ nocase ascii wide
                        $string6 = "Accenture/Spartacus" nocase ascii wide
                        $string7 = /Assets\/solution\/dllmain\.cpp/ nocase ascii wide
                        $string8 = /Data\\VulnerableCOM\.csv/ nocase ascii wide
                        $string9 = /exports\s\-\-dll\s.{0,1000}\.dll\s\-\-prototypes\s\.\/Assets\/prototypes\.csv/
                        $string10 = /help\\dll\.txt/ nocase ascii wide
                        $string11 = "--mode com --acl --csv " nocase ascii wide
                        $string12 = "--mode com --procmon " nocase ascii wide
                        $string13 = "--mode dll --existing --pml " nocase ascii wide
                        $string14 = "--mode dll --procmon " nocase ascii wide
                        $string15 = /\-\-mode\sproxy\s\-\-action\sprototypes\s\-\-path\s.{0,1000}prototypes\.csv/ nocase ascii wide
                        $string16 = /\-\-mode\sproxy\s\-\-dll\s.{0,1000}\.dll.{0,1000}\-\-external\-resources/ nocase ascii wide
                        $string17 = /\-\-mode\sproxy\s\-\-ghidra\s.{0,1000}\-\-dll\s/ nocase ascii wide
                        $string18 = /Spartacus\.exe\s\-\-mode\sproxy/ nocase ascii wide
                        $string19 = /Spartacus\-main\.zip/ nocase ascii wide
                        $string20 = /spartacus\-proxy\-.{0,1000}\.log/ nocase ascii wide
                        $string21 = /Spartacus\-v2\..{0,1000}\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}