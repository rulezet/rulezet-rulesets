rule rule_BITSInject_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'BITSInject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BITSInject"
        rule_category = "signature_keyword"

    strings:
                        $string1_BITSInject_signature_keyword = /Behavior\:Win32\/BitsInject\.A\!attk/ nocase ascii wide

    condition:
        any of them
}