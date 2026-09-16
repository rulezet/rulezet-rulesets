rule rule_ADSyncDecrypt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADSyncDecrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADSyncDecrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADSyncDecrypt_offensive_tool_keyword = /\\ADSyncDecrypt\\/ nocase ascii wide
                        $string2_ADSyncDecrypt_offensive_tool_keyword = ">ADSyncDecrypt<" nocase ascii wide
                        $string3_ADSyncDecrypt_offensive_tool_keyword = /ADSyncDecrypt\.exe/ nocase ascii wide
                        $string4_ADSyncDecrypt_offensive_tool_keyword = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9nZW50aWxraXdpL21pbWlrYXR6L3JlbGVhc2VzL2xhdGVzdA==" nocase ascii wide

    condition:
        any of them
}