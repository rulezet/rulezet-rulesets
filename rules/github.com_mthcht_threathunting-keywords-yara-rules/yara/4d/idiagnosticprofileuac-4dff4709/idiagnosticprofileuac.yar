rule IDiagnosticProfileUAC
{
    meta:
        description = "Detection patterns for the tool 'IDiagnosticProfileUAC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IDiagnosticProfileUAC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/IDiagnosticProfileUAC" nocase ascii wide
                        $string2 = /\\IDiagnosticProfileUAC/ nocase ascii wide
                        $string3 = /C\:\\Uac\\results\.cab/ nocase ascii wide
                        $string4 = /IDiagnosticProfileUAC\.git/ nocase ascii wide
                        $string5 = "IDiagnosticProfileUAC-main" nocase ascii wide

    condition:
        any of them
}