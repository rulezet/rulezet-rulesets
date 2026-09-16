rule rule_ntdsutil_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ntdsutil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntdsutil"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ntdsutil_greyware_tool_keyword = /\\system32\.zip/ nocase ascii wide
                        $string2_ntdsutil_greyware_tool_keyword = /ac\si\sntds.{0,1000}\s.{0,1000}create\sfull/ nocase ascii wide
                        $string3_ntdsutil_greyware_tool_keyword = "ntdsutil \"ac in ntds\" roles" nocase ascii wide
                        $string4_ntdsutil_greyware_tool_keyword = "ntdsutil \"activate instance ntds\" authoritative restore" nocase ascii wide
                        $string5_ntdsutil_greyware_tool_keyword = /ntdsutil\s.{0,1000}activate\sinstance\sntds.{0,1000}\sifm/ nocase ascii wide
                        $string6_ntdsutil_greyware_tool_keyword = /ntdsutil\s\\\\"ac\si\sntds\\\\"/ nocase ascii wide
                        $string7_ntdsutil_greyware_tool_keyword = "ntdsutil files" nocase ascii wide
                        $string8_ntdsutil_greyware_tool_keyword = "ntdsutil metadata cleanup" nocase ascii wide
                        $string9_ntdsutil_greyware_tool_keyword = "ntdsutil partition management" nocase ascii wide
                        $string10_ntdsutil_greyware_tool_keyword = "ntdsutil snapshot" nocase ascii wide
                        $string11_ntdsutil_greyware_tool_keyword = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}ifm.{0,1000}\s.{0,1000}create\sfull\s.{0,1000}c\:\\ProgramData/ nocase ascii wide
                        $string12_ntdsutil_greyware_tool_keyword = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}ifm.{0,1000}\s.{0,1000}create\sfull\s.{0,1000}users\\public/ nocase ascii wide
                        $string13_ntdsutil_greyware_tool_keyword = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}ifm.{0,1000}create\sfull\s.{0,1000}temp/ nocase ascii wide
                        $string14_ntdsutil_greyware_tool_keyword = /The\sdatabase\sengine\screated\sa\snew\sdatabase.{0,1000}temp\\Active\sDirectory\\ntds\.dit/ nocase ascii wide

    condition:
        any of them
}