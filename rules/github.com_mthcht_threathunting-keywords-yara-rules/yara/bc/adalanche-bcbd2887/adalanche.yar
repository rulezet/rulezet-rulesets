rule adalanche
{
    meta:
        description = "Detection patterns for the tool 'adalanche' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adalanche"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-authmode\sntlm\s\-\-username\s.{0,1000}\s\-\-password\s/ nocase ascii wide
                        $string2 = " collect activedirectory --" nocase ascii wide
                        $string3 = "/adalanche/modules/" nocase ascii wide
                        $string4 = /activedirectory\/pwns\.go/ nocase ascii wide
                        $string5 = "adalanche analyze" nocase ascii wide
                        $string6 = "adalanche collect" nocase ascii wide
                        $string7 = /adalanche\-.{0,1000}\.exe/ nocase ascii wide
                        $string8 = /Adalanche\.git/ nocase ascii wide
                        $string9 = "adalanche-collector" nocase ascii wide
                        $string10 = /adexplorer\.go/ nocase ascii wide
                        $string11 = "HasAutoAdminLogonCredentials" nocase ascii wide
                        $string12 = "HasSPNNoPreauth" nocase ascii wide
                        $string13 = /ldap_enums\.go/ nocase ascii wide
                        $string14 = "lkarlslund/Adalanche" nocase ascii wide

    condition:
        any of them
}