rule rule_acltoolkit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'acltoolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "acltoolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_acltoolkit_offensive_tool_keyword = " acltoolkit" nocase ascii wide
                        $string2_acltoolkit_offensive_tool_keyword = " give-dcsync" nocase ascii wide
                        $string3_acltoolkit_offensive_tool_keyword = /\sgive\-genericall\s.{0,1000}\s\-target\-sid\s/ nocase ascii wide
                        $string4_acltoolkit_offensive_tool_keyword = /\sset\-objectowner\s.{0,1000}\s\-target\-sid\s.{0,1000}\s\-owner\-sid\s/ nocase ascii wide
                        $string5_acltoolkit_offensive_tool_keyword = "/acltoolkit" nocase ascii wide
                        $string6_acltoolkit_offensive_tool_keyword = /\/add_groupmember\.py/ nocase ascii wide
                        $string7_acltoolkit_offensive_tool_keyword = "acltoolkit " nocase ascii wide
                        $string8_acltoolkit_offensive_tool_keyword = /acltoolkit\.git/ nocase ascii wide
                        $string9_acltoolkit_offensive_tool_keyword = "acltoolkit-ad" nocase ascii wide
                        $string10_acltoolkit_offensive_tool_keyword = "acltoolkit-main" nocase ascii wide
                        $string11_acltoolkit_offensive_tool_keyword = /give_dcsync\.py/ nocase ascii wide
                        $string12_acltoolkit_offensive_tool_keyword = /set_logon_script\.py/ nocase ascii wide

    condition:
        any of them
}