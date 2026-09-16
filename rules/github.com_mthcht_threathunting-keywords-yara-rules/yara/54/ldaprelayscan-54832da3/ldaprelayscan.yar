rule LdapRelayScan
{
    meta:
        description = "Detection patterns for the tool 'LdapRelayScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LdapRelayScan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-method\s.{0,1000}\s\-nthash\s/ nocase ascii wide
                        $string2 = /\.py\s\-method\sBOTH\s\-dc\-ip\s/ nocase ascii wide
                        $string3 = /\.py\s\-method\sLDAPS\s\-dc\-ip\s/ nocase ascii wide
                        $string4 = /\/LdapRelayScan\.git/ nocase ascii wide
                        $string5 = "037abc006fd6d9877d3f63baa4d32ebedd18b5a1ce6f51c22aa0d18c7ad1e352" nocase ascii wide
                        $string6 = /LdapRelayScan\.py/ nocase ascii wide
                        $string7 = "LdapRelayScan-main" nocase ascii wide
                        $string8 = "zyn3rgy/LdapRelayScan" nocase ascii wide

    condition:
        any of them
}