rule Powertool
{
    meta:
        description = "Detection patterns for the tool 'Powertool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powertool"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.Win32\.ToolPow/ nocase ascii wide

    condition:
        any of them
}