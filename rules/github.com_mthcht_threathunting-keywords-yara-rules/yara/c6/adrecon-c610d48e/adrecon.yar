rule adrecon
{
    meta:
        description = "Detection patterns for the tool 'adrecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adrecon"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "HackTool:PowerShell/ADRecon" nocase ascii wide

    condition:
        any of them
}