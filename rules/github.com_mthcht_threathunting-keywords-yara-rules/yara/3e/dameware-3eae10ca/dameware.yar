rule Dameware
{
    meta:
        description = "Detection patterns for the tool 'Dameware' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dameware"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /RemoteAccess\:Win32\/DameWareMiniRemoteControl\.B/ nocase ascii wide

    condition:
        any of them
}