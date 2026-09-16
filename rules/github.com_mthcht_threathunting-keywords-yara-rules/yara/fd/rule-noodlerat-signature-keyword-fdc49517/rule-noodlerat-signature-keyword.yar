rule rule_NoodleRAT_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'NoodleRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoodleRAT"
        rule_category = "signature_keyword"

    strings:
                        $string1_NoodleRAT_signature_keyword = /Linux\.Cloudsnooper/ nocase ascii wide
                        $string2_NoodleRAT_signature_keyword = /Linux\.NOODLERAT/ nocase ascii wide
                        $string3_NoodleRAT_signature_keyword = /Win\.NOODLERAT/ nocase ascii wide

    condition:
        any of them
}