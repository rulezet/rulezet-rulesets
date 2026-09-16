rule BITSInject
{
    meta:
        description = "Detection patterns for the tool 'BITSInject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BITSInject"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sBITSInject\.py/ nocase ascii wide
                        $string2 = /\sBITSJobPayloads\.py/ nocase ascii wide
                        $string3 = /\/BITSInject\.git/ nocase ascii wide
                        $string4 = /\/BITSInject\.py/ nocase ascii wide
                        $string5 = /\/BITSJobPayloads\.py/ nocase ascii wide
                        $string6 = /\\BITSInject\.py/ nocase ascii wide
                        $string7 = /\\BITSInject\-master/ nocase ascii wide
                        $string8 = /\\BITSJobPayloads\.py/ nocase ascii wide
                        $string9 = "09e0c32321b7bc4b6d95f4a36d9030ce2333d67ffff15e4ff51631c3c4aa319d" nocase ascii wide
                        $string10 = "880b020391f6702f07775929110ac0f9aff0cec6fce2bd8e1e079bcace792e33" nocase ascii wide
                        $string11 = "93362035A00C104A84F3B17E7B499CD700000000020000000000000000000000C00A1281B535EF499" nocase ascii wide
                        $string12 = "SafeBreach-Labs/BITSInject" nocase ascii wide
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