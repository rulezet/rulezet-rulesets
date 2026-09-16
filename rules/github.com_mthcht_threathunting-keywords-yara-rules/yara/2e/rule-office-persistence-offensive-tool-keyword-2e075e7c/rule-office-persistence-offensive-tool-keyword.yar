rule rule_Office_Persistence_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Office-Persistence' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Office-Persistence"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Office_Persistence_offensive_tool_keyword = /\sOfficePersistence\.ps1/ nocase ascii wide
                        $string2_Office_Persistence_offensive_tool_keyword = /\#\sPop\sup\sthe\scalculator\swhen\syou\sstart\sexcel\.exe/ nocase ascii wide
                        $string3_Office_Persistence_offensive_tool_keyword = /\#\sPop\sup\sthe\scalculator\swhen\syou\sstart\spowerpoint\.exe/ nocase ascii wide
                        $string4_Office_Persistence_offensive_tool_keyword = /\#\sPop\sup\sthe\scalculator\swhen\syou\sstart\swinword\.exe/ nocase ascii wide
                        $string5_Office_Persistence_offensive_tool_keyword = /\$calcwllx64\s\=\s\\"TVqQAAMAAAAEAAAA\/\/8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\+AAAAA4/ nocase ascii wide
                        $string6_Office_Persistence_offensive_tool_keyword = /\$calcwllx86\s\=\s\\"TVqQAAMAAAAEAAAA\/\/8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyAAAAA4/ nocase ascii wide
                        $string7_Office_Persistence_offensive_tool_keyword = /\/Office\-Persistence\.git/ nocase ascii wide
                        $string8_Office_Persistence_offensive_tool_keyword = /\/OfficePersistence\.ps1/ nocase ascii wide
                        $string9_Office_Persistence_offensive_tool_keyword = /\/Office\-Persistence\/master\/calc\.ppa/ nocase ascii wide
                        $string10_Office_Persistence_offensive_tool_keyword = /\\OfficePersistence\.ps1/ nocase ascii wide
                        $string11_Office_Persistence_offensive_tool_keyword = "3gstudent/Office-Persistence" nocase ascii wide
                        $string12_Office_Persistence_offensive_tool_keyword = "63a6bad64de560056ed496b6b7103056e4bdaf19f49011120997a5b87d141940" nocase ascii wide

    condition:
        any of them
}