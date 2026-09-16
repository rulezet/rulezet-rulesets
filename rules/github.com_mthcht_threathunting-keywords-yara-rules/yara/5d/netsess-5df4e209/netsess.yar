rule NetSess
{
    meta:
        description = "Detection patterns for the tool 'NetSess' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetSess"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.Win32\.JoeWare/ nocase ascii wide

    condition:
        any of them
}