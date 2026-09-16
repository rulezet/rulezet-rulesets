rule sysmonquiet
{
    meta:
        description = "Detection patterns for the tool 'sysmonquiet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sysmonquiet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/SysmonQuiet" nocase ascii wide
                        $string2 = "Sysmon is being suffocated" nocase ascii wide
                        $string3 = "Sysmon is quiet now!" nocase ascii wide
                        $string4 = /sysmonquiet\./ nocase ascii wide
                        $string5 = "SysmonQuiet-main" nocase ascii wide
                        $string6 = "Yay! No SYSMON here!" nocase ascii wide

    condition:
        any of them
}