rule acltoolkit
{
    meta:
        description = "Detection patterns for the tool 'acltoolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "acltoolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " acltoolkit" nocase ascii wide
                        $string2 = " give-dcsync" nocase ascii wide
                        $string3 = /\sgive\-genericall\s.{0,1000}\s\-target\-sid\s/ nocase ascii wide
                        $string4 = /\sset\-objectowner\s.{0,1000}\s\-target\-sid\s.{0,1000}\s\-owner\-sid\s/ nocase ascii wide
                        $string5 = "/acltoolkit" nocase ascii wide
                        $string6 = /\/add_groupmember\.py/ nocase ascii wide
                        $string7 = "acltoolkit " nocase ascii wide
                        $string8 = /acltoolkit\.git/ nocase ascii wide
                        $string9 = "acltoolkit-ad" nocase ascii wide
                        $string10 = "acltoolkit-main" nocase ascii wide
                        $string11 = /give_dcsync\.py/ nocase ascii wide
                        $string12 = /set_logon_script\.py/ nocase ascii wide

    condition:
        any of them
}