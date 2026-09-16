rule Checkmate
{
    meta:
        description = "Detection patterns for the tool 'Checkmate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Checkmate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-onefile\sCheckmate\.py/ nocase ascii wide
                        $string2 = "9be92d43d374ae72fbc28b078e1083e674ebe4da30f4f815aa9d86150b4fe024" nocase ascii wide
                        $string3 = /C\:\\Users\\username\\command_log\.txt/ nocase ascii wide
                        $string4 = /C\:\\Users\\username\\payload\.exe/ nocase ascii wide
                        $string5 = "e50c620c59b9a402d924b65695c6ee723cf10bbf65c542416888776f3b58282f" nocase ascii wide
                        $string6 = /os\.system\(\'reg\sadd\s\\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet\sSettings\\"\s\/v\s\\"EnableSmartScreenFilter\\"\s\/t\sREG_DWORD\s\/d\s\\"0\\"\s\/f\'\)/ nocase ascii wide
                        $string7 = "S3N4T0R-0X0/Checkmate" nocase ascii wide

    condition:
        any of them
}