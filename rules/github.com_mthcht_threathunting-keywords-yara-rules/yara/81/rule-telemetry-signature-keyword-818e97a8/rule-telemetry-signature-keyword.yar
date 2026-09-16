rule rule_Telemetry_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Telemetry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Telemetry"
        rule_category = "signature_keyword"

    strings:
                        $string1_Telemetry_signature_keyword = /Hacktool\.Msil\.Telemetry/ nocase ascii wide

    condition:
        any of them
}