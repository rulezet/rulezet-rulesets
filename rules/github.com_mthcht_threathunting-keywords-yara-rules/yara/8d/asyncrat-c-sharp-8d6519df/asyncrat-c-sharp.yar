rule AsyncRAT_C_Sharp
{
    meta:
        description = "Detection patterns for the tool 'AsyncRAT-C-Sharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AsyncRAT-C-Sharp"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "RemoteAccess:MSIL/AsyncRAT" nocase ascii wide

    condition:
        any of them
}