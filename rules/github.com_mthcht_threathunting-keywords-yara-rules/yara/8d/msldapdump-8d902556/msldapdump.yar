rule msldapdump
{
    meta:
        description = "Detection patterns for the tool 'msldapdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msldapdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.adminusers\.txt/ nocase ascii wide
                        $string2 = /\.asreproast\.txt/ nocase ascii wide
                        $string3 = /\.kerberoast\.txt/ nocase ascii wide
                        $string4 = /\.ldapdump\.txt/ nocase ascii wide
                        $string5 = /\.unconstrained\.txt/ nocase ascii wide
                        $string6 = "/msLDAPDump" nocase ascii wide
                        $string7 = /msLDAPDump\.py/ nocase ascii wide

    condition:
        any of them
}