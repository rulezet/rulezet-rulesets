rule rule_adalanche_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adalanche' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adalanche"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adalanche_offensive_tool_keyword = /\s\-\-authmode\sntlm\s\-\-username\s.{0,1000}\s\-\-password\s/ nocase ascii wide
                        $string2_adalanche_offensive_tool_keyword = " collect activedirectory --" nocase ascii wide
                        $string3_adalanche_offensive_tool_keyword = "/adalanche/modules/" nocase ascii wide
                        $string4_adalanche_offensive_tool_keyword = /activedirectory\/pwns\.go/ nocase ascii wide
                        $string5_adalanche_offensive_tool_keyword = "adalanche analyze" nocase ascii wide
                        $string6_adalanche_offensive_tool_keyword = "adalanche collect" nocase ascii wide
                        $string7_adalanche_offensive_tool_keyword = /adalanche\-.{0,1000}\.exe/ nocase ascii wide
                        $string8_adalanche_offensive_tool_keyword = /Adalanche\.git/ nocase ascii wide
                        $string9_adalanche_offensive_tool_keyword = "adalanche-collector" nocase ascii wide
                        $string10_adalanche_offensive_tool_keyword = /adexplorer\.go/ nocase ascii wide
                        $string11_adalanche_offensive_tool_keyword = "HasAutoAdminLogonCredentials" nocase ascii wide
                        $string12_adalanche_offensive_tool_keyword = "HasSPNNoPreauth" nocase ascii wide
                        $string13_adalanche_offensive_tool_keyword = /ldap_enums\.go/ nocase ascii wide
                        $string14_adalanche_offensive_tool_keyword = "lkarlslund/Adalanche" nocase ascii wide

    condition:
        any of them
}