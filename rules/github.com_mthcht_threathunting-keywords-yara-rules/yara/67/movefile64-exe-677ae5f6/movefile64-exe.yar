rule movefile64_exe
{
    meta:
        description = "Detection patterns for the tool 'movefile64.exe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "movefile64.exe"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /movefile64\.exe\s\/nobanner\s.{0,1000}\.dll\sC\:\\Windows\\System32\\amsi\.dll/ nocase ascii wide

    condition:
        any of them
}