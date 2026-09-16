rule rule_CertStealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CertStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CertStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CertStealer_offensive_tool_keyword = "/CertStealer" nocase ascii wide
                        $string2_CertStealer_offensive_tool_keyword = /CertStealer\.csproj/ nocase ascii wide
                        $string3_CertStealer_offensive_tool_keyword = /CertStealer\.exe/ nocase ascii wide
                        $string4_CertStealer_offensive_tool_keyword = /CertStealer\.sln/ nocase ascii wide

    condition:
        any of them
}