rule Farmer
{
    meta:
        description = "Detection patterns for the tool 'Farmer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Farmer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Farmer\.git/ nocase ascii wide
                        $string2 = /\\Fertliser\.exe/ nocase ascii wide
                        $string3 = /\\Fertliser\.pdb/ nocase ascii wide
                        $string4 = /c\:\\windows\\temp\\test\.tmp\sfarmer/ nocase ascii wide
                        $string5 = /crop\.exe\s\\\\.{0,1000}\\.{0,1000}\.lnk\s\\\\.{0,1000}\\harvest\s\\\\.{0,1000}\\harvest/ nocase ascii wide
                        $string6 = /farmer\.exe\s.{0,1000}\\windows\\temp/ nocase ascii wide
                        $string7 = /farmer\.exe\s8888\s60/ nocase ascii wide
                        $string8 = /Farmer\\Farmer\.csproj/ nocase ascii wide
                        $string9 = /Farmer\-main\.zip/ nocase ascii wide
                        $string10 = /Fertiliser\.exe\s\\\\/ nocase ascii wide
                        $string11 = /harvestcrop\.exe\s.{0,1000}\s/ nocase ascii wide
                        $string12 = "mdsecactivebreach/Farmer" nocase ascii wide

    condition:
        any of them
}