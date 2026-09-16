rule rule_IDiagnosticProfileUAC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IDiagnosticProfileUAC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IDiagnosticProfileUAC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_IDiagnosticProfileUAC_offensive_tool_keyword = "/IDiagnosticProfileUAC" nocase ascii wide
                        $string2_IDiagnosticProfileUAC_offensive_tool_keyword = /\\IDiagnosticProfileUAC/ nocase ascii wide
                        $string3_IDiagnosticProfileUAC_offensive_tool_keyword = /C\:\\Uac\\results\.cab/ nocase ascii wide
                        $string4_IDiagnosticProfileUAC_offensive_tool_keyword = /IDiagnosticProfileUAC\.git/ nocase ascii wide
                        $string5_IDiagnosticProfileUAC_offensive_tool_keyword = "IDiagnosticProfileUAC-main" nocase ascii wide

    condition:
        any of them
}