rule NativeBypassCredGuard
{
    meta:
        description = "Detection patterns for the tool 'NativeBypassCredGuard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NativeBypassCredGuard"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/NativeBypassCredGuard\.git/ nocase ascii wide
                        $string2 = /\[\+\]\sEnable\sSeDebugPrivilege\:\s\\tOK/ nocase ascii wide
                        $string3 = /\\NativeBypassCredGuard\.sln/ nocase ascii wide
                        $string4 = /\\NativeBypassCredGuard_C\+\+/ nocase ascii wide
                        $string5 = /\\NativeBypassCredGuard\-main/ nocase ascii wide
                        $string6 = "0614ec0ae3a38dd774d2e03dfeb05bad8e2c573f1943ab951c6129825bde4df8" nocase ascii wide
                        $string7 = "1d294d6fcae8b9d57d60166f102fd91d63ad88def2ab80eadcac22750f6f3c47" nocase ascii wide
                        $string8 = "28bba6f4d8a170a77e383fe09fcc3d5258496fb45b0c226891cc51f8b96ef489" nocase ascii wide
                        $string9 = "c4d31433-5017-4b5e-956b-8a540520986c" nocase ascii wide
                        $string10 = "E383DFEA-EC22-4667-9434-3F2591A03740" nocase ascii wide
                        $string11 = /NativeBypassCredGuard\.exe/ nocase ascii wide
                        $string12 = "ricardojoserf/NativeBypassCredGuard" nocase ascii wide
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