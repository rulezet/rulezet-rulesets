rule WMIHACKER
{
    meta:
        description = "Detection patterns for the tool 'WMIHACKER' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMIHACKER"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.VBS\.WMIHACKER/ nocase ascii wide

    condition:
        any of them
}