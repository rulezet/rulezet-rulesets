rule rule_netpass_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'netpass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netpass"
        rule_category = "signature_keyword"

    strings:
                        $string1_netpass_signature_keyword = /HackTool\:Win32\/Netpasss\.AB\!MTB/ nocase ascii wide

    condition:
        any of them
}