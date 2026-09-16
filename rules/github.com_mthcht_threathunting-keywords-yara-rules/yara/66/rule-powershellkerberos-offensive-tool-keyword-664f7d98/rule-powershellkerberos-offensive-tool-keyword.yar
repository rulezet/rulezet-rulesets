rule rule_PowershellKerberos_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowershellKerberos' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowershellKerberos"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowershellKerberos_offensive_tool_keyword = /\sdumper\.ps1/ nocase ascii wide
                        $string2_PowershellKerberos_offensive_tool_keyword = /\/PowershellKerberos\.git/ nocase ascii wide
                        $string3_PowershellKerberos_offensive_tool_keyword = /\\dumper\.ps1/ nocase ascii wide
                        $string4_PowershellKerberos_offensive_tool_keyword = /\\injector\.ps1\s1\s/ nocase ascii wide
                        $string5_PowershellKerberos_offensive_tool_keyword = /\\injector\.ps1\s2\s/ nocase ascii wide
                        $string6_PowershellKerberos_offensive_tool_keyword = /\\PowershellKerberos/ nocase ascii wide
                        $string7_PowershellKerberos_offensive_tool_keyword = /injector\.ps1.{0,1000}\.kirbi/ nocase ascii wide
                        $string8_PowershellKerberos_offensive_tool_keyword = "PowershellKerberos-main" nocase ascii wide

    condition:
        any of them
}