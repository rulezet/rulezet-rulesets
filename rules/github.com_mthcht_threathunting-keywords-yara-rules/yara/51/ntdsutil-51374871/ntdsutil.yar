rule ntdsutil
{
    meta:
        description = "Detection patterns for the tool 'ntdsutil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntdsutil"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\system32\.zip/ nocase ascii wide
                        $string2 = /ac\si\sntds.{0,1000}\s.{0,1000}create\sfull/ nocase ascii wide
                        $string3 = "ntdsutil \"ac in ntds\" roles" nocase ascii wide
                        $string4 = "ntdsutil \"activate instance ntds\" authoritative restore" nocase ascii wide
                        $string5 = /ntdsutil\s.{0,1000}activate\sinstance\sntds.{0,1000}\sifm/ nocase ascii wide
                        $string6 = /ntdsutil\s\\\\"ac\si\sntds\\\\"/ nocase ascii wide
                        $string7 = "ntdsutil files" nocase ascii wide
                        $string8 = "ntdsutil metadata cleanup" nocase ascii wide
                        $string9 = "ntdsutil partition management" nocase ascii wide
                        $string10 = "ntdsutil snapshot" nocase ascii wide
                        $string11 = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}ifm.{0,1000}\s.{0,1000}create\sfull\s.{0,1000}c\:\\ProgramData/ nocase ascii wide
                        $string12 = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}ifm.{0,1000}\s.{0,1000}create\sfull\s.{0,1000}users\\public/ nocase ascii wide
                        $string13 = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}ifm.{0,1000}create\sfull\s.{0,1000}temp/ nocase ascii wide
                        $string14 = /The\sdatabase\sengine\screated\sa\snew\sdatabase.{0,1000}temp\\Active\sDirectory\\ntds\.dit/ nocase ascii wide

    condition:
        any of them
}