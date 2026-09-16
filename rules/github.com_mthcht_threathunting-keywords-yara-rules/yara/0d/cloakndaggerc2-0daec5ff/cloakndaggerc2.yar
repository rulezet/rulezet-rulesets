rule CloakNDaggerC2
{
    meta:
        description = "Detection patterns for the tool 'CloakNDaggerC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CloakNDaggerC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/CloakNDaggerC2" nocase ascii wide
                        $string2 = /\\CloakNDaggerC2/ nocase ascii wide
                        $string3 = "CloakNDaggerC2-main" nocase ascii wide
                        $string4 = /http\:\/\/192\.168\.1\.179\:8000\/session/ nocase ascii wide
                        $string5 = "nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4pz" nocase ascii wide

    condition:
        any of them
}