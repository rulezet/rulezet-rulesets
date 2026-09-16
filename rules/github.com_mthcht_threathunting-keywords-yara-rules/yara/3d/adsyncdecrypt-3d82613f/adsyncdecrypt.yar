rule ADSyncDecrypt
{
    meta:
        description = "Detection patterns for the tool 'ADSyncDecrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADSyncDecrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\ADSyncDecrypt\\/ nocase ascii wide
                        $string2 = ">ADSyncDecrypt<" nocase ascii wide
                        $string3 = /ADSyncDecrypt\.exe/ nocase ascii wide
                        $string4 = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9nZW50aWxraXdpL21pbWlrYXR6L3JlbGVhc2VzL2xhdGVzdA==" nocase ascii wide

    condition:
        any of them
}