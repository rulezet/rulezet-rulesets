rule NoodleRAT
{
    meta:
        description = "Detection patterns for the tool 'NoodleRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoodleRAT"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Linux\.Cloudsnooper/ nocase ascii wide
                        $string2 = /Linux\.NOODLERAT/ nocase ascii wide
                        $string3 = /Win\.NOODLERAT/ nocase ascii wide

    condition:
        any of them
}