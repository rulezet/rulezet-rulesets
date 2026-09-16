rule susinternals
{
    meta:
        description = "Detection patterns for the tool 'susinternals' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "susinternals"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\spsexecsvc\.py/ nocase ascii wide
                        $string2 = /PSEXECSVC19\=b64decode\(/ nocase ascii wide
                        $string3 = /\/psexecsvc\.py/ nocase ascii wide
                        $string4 = /\\psexecsvc\.py/ nocase ascii wide
                        $string5 = "fcb2f607771f185531790722ac8e3a924146186bbd3d9e03a7a793545772bdf2" nocase ascii wide
                        $string6 = "PSExecSVC remote orchestrator" nocase ascii wide
                        $string7 = "Received version from PSEXECSVC: " nocase ascii wide
                        $string8 = "Sending init packet to PSEXECSVC" nocase ascii wide
                        $string9 = "Sending PSExecSVC version 190 " nocase ascii wide
                        $string10 = "sensepost/susinternals" nocase ascii wide
                        $string11 = "VqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAByxaEKNqTPWTakz1k2pM9ZP9xLWRGkz1k/3FpZJqTPWT/cXFkhpM9ZNqTOWeikz1k/3ExZs6TPWT/cW1k3pM9ZP9xeWTekz1lSaWNoNqTPWQAAAAAAAAAAUEUAAEwBBAA8EQBSAAAAAAAAAADgAAMBCwEJAAAcAg" nocase ascii wide

    condition:
        any of them
}