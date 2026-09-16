rule ForgeCert
{
    meta:
        description = "Detection patterns for the tool 'ForgeCert' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ForgeCert"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-CaCertPath\s.{0,1000}\.pfx\s\-\-CaCertPassword\s/ nocase ascii wide
                        $string2 = /\s\-\-NewCertPath\s.{0,1000}\.pfx\s\-\-NewCertPassword\s/ nocase ascii wide
                        $string3 = /\/ForgeCert\.exe/ nocase ascii wide
                        $string4 = /\/ForgeCert\.git/ nocase ascii wide
                        $string5 = /\\ForgeCert\.exe/ nocase ascii wide
                        $string6 = /\\ForgeCert\.pdb/ nocase ascii wide
                        $string7 = "bd346689-8ee6-40b3-858b-4ed94f08d40a" nocase ascii wide
                        $string8 = "ForgeCert-main" nocase ascii wide
                        $string9 = "GhostPack/ForgeCert" nocase ascii wide
                        $string10 = "'Product'>ForgeCert" nocase ascii wide

    condition:
        any of them
}