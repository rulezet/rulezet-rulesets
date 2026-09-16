rule ldapdomaindump
{
    meta:
        description = "Detection patterns for the tool 'ldapdomaindump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapdomaindump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " domainDumper" nocase ascii wide
                        $string2 = /\/john\.git/ nocase ascii wide
                        $string3 = "bin/ldd2pretty" nocase ascii wide
                        $string4 = /dirkjan\@sanoweb\.nl/ nocase ascii wide
                        $string5 = "domainDumpConfig" nocase ascii wide
                        $string6 = "getAllUserSpns" nocase ascii wide
                        $string7 = "ldapdomaindump" nocase ascii wide
                        $string8 = "ldd2bloodhound" nocase ascii wide

    condition:
        any of them
}