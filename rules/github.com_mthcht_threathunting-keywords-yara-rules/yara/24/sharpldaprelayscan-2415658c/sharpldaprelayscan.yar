rule SharpLdapRelayScan
{
    meta:
        description = "Detection patterns for the tool 'SharpLdapRelayScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpLdapRelayScan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-m\sLDAPS/ nocase ascii wide
                        $string2 = "SharpLdapRelayScan" nocase ascii wide

    condition:
        any of them
}