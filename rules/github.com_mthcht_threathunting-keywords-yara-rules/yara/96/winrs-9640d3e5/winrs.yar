rule winrs
{
    meta:
        description = "Detection patterns for the tool 'winrs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "winrs"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /winrs\s\-r\:.{0,1000}cmd\s\/c\s/ nocase ascii wide
                        $string2 = /winrs\s\-r\:.{0,1000}powershell\s\-/ nocase ascii wide
                        $string3 = /winrs\s\-r\:.{0,1000}whoami/ nocase ascii wide

    condition:
        any of them
}