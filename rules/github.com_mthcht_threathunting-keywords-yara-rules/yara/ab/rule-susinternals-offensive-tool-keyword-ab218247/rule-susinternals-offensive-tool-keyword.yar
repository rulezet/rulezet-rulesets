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
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}