rule rule_shhmon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'shhmon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shhmon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_shhmon_offensive_tool_keyword = "/Shhmon/" nocase ascii wide
                        $string2_shhmon_offensive_tool_keyword = /\\Shhmon\./ nocase ascii wide
                        $string3_shhmon_offensive_tool_keyword = "matterpreter/Shhmon" nocase ascii wide
                        $string4_shhmon_offensive_tool_keyword = /Shhmon\.csproj/ nocase ascii wide
                        $string5_shhmon_offensive_tool_keyword = /Shhmon\.exe/ nocase ascii wide
                        $string6_shhmon_offensive_tool_keyword = /Shhmon\.git/ nocase ascii wide
                        $string7_shhmon_offensive_tool_keyword = /sshmon.{0,1000}hunt/ nocase ascii wide
                        $string8_shhmon_offensive_tool_keyword = /sshmon.{0,1000}kill/ nocase ascii wide

    condition:
        any of them
}