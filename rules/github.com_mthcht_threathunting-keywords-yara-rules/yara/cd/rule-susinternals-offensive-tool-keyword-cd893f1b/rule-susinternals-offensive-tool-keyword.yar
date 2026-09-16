rule rule_susinternals_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'susinternals' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "susinternals"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_susinternals_offensive_tool_keyword = /\spsexecsvc\.py/ nocase ascii wide
                        $string2_susinternals_offensive_tool_keyword = /PSEXECSVC19\=b64decode\(/ nocase ascii wide
                        $string3_susinternals_offensive_tool_keyword = /\/psexecsvc\.py/ nocase ascii wide
                        $string4_susinternals_offensive_tool_keyword = /\\psexecsvc\.py/ nocase ascii wide
                        $string5_susinternals_offensive_tool_keyword = "fcb2f607771f185531790722ac8e3a924146186bbd3d9e03a7a793545772bdf2" nocase ascii wide
                        $string6_susinternals_offensive_tool_keyword = "PSExecSVC remote orchestrator" nocase ascii wide
                        $string7_susinternals_offensive_tool_keyword = "Received version from PSEXECSVC: " nocase ascii wide
                        $string8_susinternals_offensive_tool_keyword = "Sending init packet to PSEXECSVC" nocase ascii wide
                        $string9_susinternals_offensive_tool_keyword = "Sending PSExecSVC version 190 " nocase ascii wide
                        $string10_susinternals_offensive_tool_keyword = "sensepost/susinternals" nocase ascii wide
                        $string11_susinternals_offensive_tool_keyword = "VqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAByxaEKNqTPWTakz1k2pM9ZP9xLWRGkz1k/3FpZJqTPWT/cXFkhpM9ZNqTOWeikz1k/3ExZs6TPWT/cW1k3pM9ZP9xeWTekz1lSaWNoNqTPWQAAAAAAAAAAUEUAAEwBBAA8EQBSAAAAAAAAAADgAAMBCwEJAAAcAg" nocase ascii wide

    condition:
        any of them
}