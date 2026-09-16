rule pastehakk
{
    meta:
        description = "Detection patterns for the tool 'pastehakk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastehakk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\spastehakk\.sh/
                        $string2 = /\$\{White\}A\stool\sto\sperform\sclipboard\spoisoning\sattack/
                        $string3 = /\$Green\sInfecting\shtml\sfile/
                        $string4 = /\/pastehakk\.git/ nocase ascii wide
                        $string5 = /\/pastehakk\.sh/
                        $string6 = "3xploitGuy/pastehakk" nocase ascii wide
                        $string7 = "53a9c6eed3ee5ed0ea6fe900bbcdac2b9c0709c57c8d82688ef32f7e2b784f60"
                        $string8 = "clear; history -c"
                        $string9 = "pastehakk_generate"
                        $string10 = /sandeshyadavm46\@gmail\.com/
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