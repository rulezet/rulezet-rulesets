rule rule_RemoteUtilities_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'RemoteUtilities' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemoteUtilities"
        rule_category = "signature_keyword"

    strings:
                        $string1_RemoteUtilities_signature_keyword = /RemoteAdmin\.RemoteUtilities/ nocase ascii wide
                        $string2_RemoteUtilities_signature_keyword = /Trojan\.RemoteUtilitiesRAT/ nocase ascii wide

    condition:
        any of them
}