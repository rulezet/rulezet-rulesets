rule Office_Persistence
{
    meta:
        description = "Detection patterns for the tool 'Office-Persistence' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Office-Persistence"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sOfficePersistence\.ps1/ nocase ascii wide
                        $string2 = /\#\sPop\sup\sthe\scalculator\swhen\syou\sstart\sexcel\.exe/ nocase ascii wide
                        $string3 = /\#\sPop\sup\sthe\scalculator\swhen\syou\sstart\spowerpoint\.exe/ nocase ascii wide
                        $string4 = /\#\sPop\sup\sthe\scalculator\swhen\syou\sstart\swinword\.exe/ nocase ascii wide
                        $string5 = /\$calcwllx64\s\=\s\\"TVqQAAMAAAAEAAAA\/\/8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\+AAAAA4/ nocase ascii wide
                        $string6 = /\$calcwllx86\s\=\s\\"TVqQAAMAAAAEAAAA\/\/8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyAAAAA4/ nocase ascii wide
                        $string7 = /\/Office\-Persistence\.git/ nocase ascii wide
                        $string8 = /\/OfficePersistence\.ps1/ nocase ascii wide
                        $string9 = /\/Office\-Persistence\/master\/calc\.ppa/ nocase ascii wide
                        $string10 = /\\OfficePersistence\.ps1/ nocase ascii wide
                        $string11 = "3gstudent/Office-Persistence" nocase ascii wide
                        $string12 = "63a6bad64de560056ed496b6b7103056e4bdaf19f49011120997a5b87d141940" nocase ascii wide

    condition:
        any of them
}