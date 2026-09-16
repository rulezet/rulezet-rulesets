rule BITSInject
{
    meta:
        description = "Detection patterns for the tool 'BITSInject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BITSInject"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Behavior\:Win32\/BitsInject\.A\!attk/ nocase ascii wide

    condition:
        any of them
}