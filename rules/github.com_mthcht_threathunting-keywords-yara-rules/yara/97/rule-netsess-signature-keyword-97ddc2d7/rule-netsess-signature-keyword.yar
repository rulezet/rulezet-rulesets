rule rule_NetSess_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'NetSess' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetSess"
        rule_category = "signature_keyword"

    strings:
                        $string1_NetSess_signature_keyword = /HackTool\.Win32\.JoeWare/ nocase ascii wide

    condition:
        any of them
}