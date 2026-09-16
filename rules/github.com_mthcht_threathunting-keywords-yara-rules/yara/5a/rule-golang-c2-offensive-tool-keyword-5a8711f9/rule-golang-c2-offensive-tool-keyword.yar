rule rule_golang_c2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'golang_c2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "golang_c2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_golang_c2_offensive_tool_keyword = /\/golang_c2\.git/ nocase ascii wide
                        $string2_golang_c2_offensive_tool_keyword = "cd golang_c2" nocase ascii wide
                        $string3_golang_c2_offensive_tool_keyword = "CREATE DATABASE C2;" nocase ascii wide
                        $string4_golang_c2_offensive_tool_keyword = "golang_c2-master" nocase ascii wide
                        $string5_golang_c2_offensive_tool_keyword = "m00zh33/golang_c2" nocase ascii wide
                        $string6_golang_c2_offensive_tool_keyword = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqqKav9bmrSMSPwnxA3ul" nocase ascii wide
                        $string7_golang_c2_offensive_tool_keyword = "MIIEpAIBAAKCAQEAqqKav9bmrSMSPwnxA3ulIleTPGiL9LGtdROute8ncU0HzPyL" nocase ascii wide
                        $string8_golang_c2_offensive_tool_keyword = /mysql\s\-u.{0,1000}\s\-p\sc2\s\<\sc2_sample\.sql/ nocase ascii wide

    condition:
        any of them
}