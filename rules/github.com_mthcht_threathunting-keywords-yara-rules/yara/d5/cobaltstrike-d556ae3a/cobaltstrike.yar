rule cobaltstrike
{
    meta:
        description = "Detection patterns for the tool 'cobaltstrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cobaltstrike"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\AppData\\Local\\Microsoft\\CLR_.{0,1000}\\UsageLogs\\.{0,1000}\.exe\.log/ nocase ascii wide
                        $string2 = /cmd\.exe\s\/c\secho\s.{0,1000}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide

    condition:
        any of them
}