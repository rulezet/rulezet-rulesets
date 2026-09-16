rule rule_ForgeCert_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ForgeCert' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ForgeCert"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ForgeCert_offensive_tool_keyword = /\s\-\-CaCertPath\s.{0,1000}\.pfx\s\-\-CaCertPassword\s/ nocase ascii wide
                        $string2_ForgeCert_offensive_tool_keyword = /\s\-\-NewCertPath\s.{0,1000}\.pfx\s\-\-NewCertPassword\s/ nocase ascii wide
                        $string3_ForgeCert_offensive_tool_keyword = /\/ForgeCert\.exe/ nocase ascii wide
                        $string4_ForgeCert_offensive_tool_keyword = /\/ForgeCert\.git/ nocase ascii wide
                        $string5_ForgeCert_offensive_tool_keyword = /\\ForgeCert\.exe/ nocase ascii wide
                        $string6_ForgeCert_offensive_tool_keyword = /\\ForgeCert\.pdb/ nocase ascii wide
                        $string7_ForgeCert_offensive_tool_keyword = "bd346689-8ee6-40b3-858b-4ed94f08d40a" nocase ascii wide
                        $string8_ForgeCert_offensive_tool_keyword = "ForgeCert-main" nocase ascii wide
                        $string9_ForgeCert_offensive_tool_keyword = "GhostPack/ForgeCert" nocase ascii wide
                        $string10_ForgeCert_offensive_tool_keyword = "'Product'>ForgeCert" nocase ascii wide

    condition:
        any of them
}