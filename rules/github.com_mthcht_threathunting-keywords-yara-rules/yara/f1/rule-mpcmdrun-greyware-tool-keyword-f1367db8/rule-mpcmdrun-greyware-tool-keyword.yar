rule rule_MpCmdRun_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MpCmdRun' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MpCmdRun"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_MpCmdRun_greyware_tool_keyword = /MpCmdRun\.exe\s\-DownloadFile\s\-url\shttp\:\/\/.{0,1000}\.exe\s\-path\s/ nocase ascii wide
                        $string2_MpCmdRun_greyware_tool_keyword = /MpCmdRun\.exe.{0,1000}\s\-disable/ nocase ascii wide
                        $string3_MpCmdRun_greyware_tool_keyword = /MpCmdRun\.exe.{0,1000}\s\-RemoveDefinitions\s\-All/ nocase ascii wide

    condition:
        any of them
}