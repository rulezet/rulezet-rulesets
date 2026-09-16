rule rule_WinSCP_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WinSCP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinSCP"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_WinSCP_greyware_tool_keyword = /\\CurrentVersion\\Uninstall\\winscp3_is1/ nocase ascii wide
                        $string2_WinSCP_greyware_tool_keyword = /\\Program\sFiles\\WinSCP/ nocase ascii wide
                        $string3_WinSCP_greyware_tool_keyword = /\\SOFTWARE\\Martin\sPrikryl\\WinSCP\s2\\/ nocase ascii wide
                        $string4_WinSCP_greyware_tool_keyword = /Temp.{0,1000}_WinSCP\-\-Portable\.zip/ nocase ascii wide
                        $string5_WinSCP_greyware_tool_keyword = /winscp\.com\s\/command\s\\"open\ssftp\:\/\// nocase ascii wide

    condition:
        any of them
}