rule rule_adconnectdump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adconnectdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adconnectdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adconnectdump_offensive_tool_keyword = /\/adconnectdump\.git/ nocase ascii wide
                        $string2_adconnectdump_offensive_tool_keyword = /adconnectdump\.py/ nocase ascii wide
                        $string3_adconnectdump_offensive_tool_keyword = "adconnectdump-master" nocase ascii wide
                        $string4_adconnectdump_offensive_tool_keyword = /ADSyncDecrypt\.exe/ nocase ascii wide
                        $string5_adconnectdump_offensive_tool_keyword = /ADSyncGather\.exe/ nocase ascii wide
                        $string6_adconnectdump_offensive_tool_keyword = /ADSyncQuery.{0,1000}ADSync\.mdf.{0,1000}\.txt/ nocase ascii wide
                        $string7_adconnectdump_offensive_tool_keyword = /decrypt\.py\s\.\\.{0,1000}\.txt\sutf\-16\-le/ nocase ascii wide
                        $string8_adconnectdump_offensive_tool_keyword = "fox-it/adconnectdump" nocase ascii wide

    condition:
        any of them
}