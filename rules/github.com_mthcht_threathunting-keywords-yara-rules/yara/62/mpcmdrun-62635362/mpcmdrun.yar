rule MpCmdRun
{
    meta:
        description = "Detection patterns for the tool 'MpCmdRun' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MpCmdRun"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /MpCmdRun\.exe.{0,1000}\s\-RemoveDefinitions\s\-All/ nocase ascii wide

    condition:
        any of them
}