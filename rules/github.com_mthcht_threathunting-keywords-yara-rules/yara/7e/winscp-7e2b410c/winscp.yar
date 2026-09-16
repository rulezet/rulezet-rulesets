rule WinSCP
{
    meta:
        description = "Detection patterns for the tool 'WinSCP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinSCP"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\CurrentVersion\\Uninstall\\winscp3_is1/ nocase ascii wide
                        $string2 = /\\Program\sFiles\\WinSCP/ nocase ascii wide
                        $string3 = /\\SOFTWARE\\Martin\sPrikryl\\WinSCP\s2\\/ nocase ascii wide
                        $string4 = /Temp.{0,1000}_WinSCP\-\-Portable\.zip/ nocase ascii wide
                        $string5 = /winscp\.com\s\/command\s\\"open\ssftp\:\/\// nocase ascii wide

    condition:
        any of them
}