rule CertStealer
{
    meta:
        description = "Detection patterns for the tool 'CertStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CertStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/CertStealer" nocase ascii wide
                        $string2 = /CertStealer\.csproj/ nocase ascii wide
                        $string3 = /CertStealer\.exe/ nocase ascii wide
                        $string4 = /CertStealer\.sln/ nocase ascii wide

    condition:
        any of them
}