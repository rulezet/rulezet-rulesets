rule rule_CloakNDaggerC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CloakNDaggerC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CloakNDaggerC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CloakNDaggerC2_offensive_tool_keyword = "/CloakNDaggerC2" nocase ascii wide
                        $string2_CloakNDaggerC2_offensive_tool_keyword = /\\CloakNDaggerC2/ nocase ascii wide
                        $string3_CloakNDaggerC2_offensive_tool_keyword = "CloakNDaggerC2-main" nocase ascii wide
                        $string4_CloakNDaggerC2_offensive_tool_keyword = /http\:\/\/192\.168\.1\.179\:8000\/session/ nocase ascii wide
                        $string5_CloakNDaggerC2_offensive_tool_keyword = "nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4pz" nocase ascii wide

    condition:
        any of them
}