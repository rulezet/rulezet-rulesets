rule Compress_Archive
{
    meta:
        description = "Detection patterns for the tool 'Compress-Archive' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Compress-Archive"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\:\\programdata\\cloud\.exe/ nocase ascii wide
                        $string2 = /Compress\-Archive\s\-Path.{0,1000}\-DestinationPath\s\$env\:TEMP/ nocase ascii wide
                        $string3 = /Compress\-Archive\s\-Path.{0,1000}\-DestinationPath.{0,1000}\:\\Windows\\Temp\\/ nocase ascii wide
                        $string4 = /Compress\-Archive\s\-Path.{0,1000}\-DestinationPath.{0,1000}\\AppData\\Local\\Temp\\\'/ nocase ascii wide

    condition:
        any of them
}