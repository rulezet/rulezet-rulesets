rule rule_ldapdomaindump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ldapdomaindump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapdomaindump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ldapdomaindump_offensive_tool_keyword = " domainDumper" nocase ascii wide
                        $string2_ldapdomaindump_offensive_tool_keyword = /\/john\.git/ nocase ascii wide
                        $string3_ldapdomaindump_offensive_tool_keyword = "bin/ldd2pretty" nocase ascii wide
                        $string4_ldapdomaindump_offensive_tool_keyword = /dirkjan\@sanoweb\.nl/ nocase ascii wide
                        $string5_ldapdomaindump_offensive_tool_keyword = "domainDumpConfig" nocase ascii wide
                        $string6_ldapdomaindump_offensive_tool_keyword = "getAllUserSpns" nocase ascii wide
                        $string7_ldapdomaindump_offensive_tool_keyword = "ldapdomaindump" nocase ascii wide
                        $string8_ldapdomaindump_offensive_tool_keyword = "ldd2bloodhound" nocase ascii wide

    condition:
        any of them
}