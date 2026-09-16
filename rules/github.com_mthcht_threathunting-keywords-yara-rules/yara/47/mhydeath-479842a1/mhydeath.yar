rule mhydeath
{
    meta:
        description = "Detection patterns for the tool 'mhydeath' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mhydeath"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/mhydeath\.git/ nocase ascii wide
                        $string2 = /\/mhydeath\.sln/ nocase ascii wide
                        $string3 = /\/mhydeath\/main\.cpp/ nocase ascii wide
                        $string4 = /\/process_killer\.cpp/ nocase ascii wide
                        $string5 = /\\mhydeath64/ nocase ascii wide
                        $string6 = /\\process_killer\.cpp/ nocase ascii wide
                        $string7 = "0D17A4B4-A7C4-49C0-99E3-B856F9F3B271" nocase ascii wide
                        $string8 = /mhydeath\.exe/ nocase ascii wide
                        $string9 = "mhydeath-master" nocase ascii wide
                        $string10 = /process_killer\.exe/ nocase ascii wide
                        $string11 = "zer0condition/mhydeath" nocase ascii wide

    condition:
        any of them
}