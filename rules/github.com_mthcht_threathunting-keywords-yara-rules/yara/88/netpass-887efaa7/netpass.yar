rule netpass
{
    meta:
        description = "Detection patterns for the tool 'netpass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netpass"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\:Win32\/Netpasss\.AB\!MTB/ nocase ascii wide

    condition:
        any of them
}