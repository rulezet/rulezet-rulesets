rule conhost_exe
{
    meta:
        description = "Detection patterns for the tool 'conhost.exe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "conhost.exe"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /conhost\.exe\s.{0,1000}\s\-\-headless/ nocase ascii wide

    condition:
        any of them
}