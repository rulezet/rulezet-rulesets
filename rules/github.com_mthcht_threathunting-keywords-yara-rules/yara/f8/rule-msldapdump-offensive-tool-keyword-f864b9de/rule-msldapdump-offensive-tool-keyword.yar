rule rule_msldapdump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'msldapdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msldapdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_msldapdump_offensive_tool_keyword = /\.adminusers\.txt/ nocase ascii wide
                        $string2_msldapdump_offensive_tool_keyword = /\.asreproast\.txt/ nocase ascii wide
                        $string3_msldapdump_offensive_tool_keyword = /\.kerberoast\.txt/ nocase ascii wide
                        $string4_msldapdump_offensive_tool_keyword = /\.ldapdump\.txt/ nocase ascii wide
                        $string5_msldapdump_offensive_tool_keyword = /\.unconstrained\.txt/ nocase ascii wide
                        $string6_msldapdump_offensive_tool_keyword = "/msLDAPDump" nocase ascii wide
                        $string7_msldapdump_offensive_tool_keyword = /msLDAPDump\.py/ nocase ascii wide

    condition:
        any of them
}