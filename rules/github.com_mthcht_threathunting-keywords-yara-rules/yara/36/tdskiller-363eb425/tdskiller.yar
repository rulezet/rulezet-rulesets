rule TDSKiller
{
    meta:
        description = "Detection patterns for the tool 'TDSKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TDSKiller"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Application\.RiskTool\.TDSSKiller\.A/ nocase ascii wide

    condition:
        any of them
}