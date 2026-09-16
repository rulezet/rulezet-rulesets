rule BlankOBF
{
    meta:
        description = "Detection patterns for the tool 'BlankOBF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlankOBF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sBlankOBFv2\.py/ nocase ascii wide
                        $string2 = /\/BlankOBF\.git/ nocase ascii wide
                        $string3 = /\/BlankOBFv2\.py/ nocase ascii wide
                        $string4 = /\\BlankOBFv2\.py/ nocase ascii wide
                        $string5 = "bc4657ac480d1f46349254c1d217dba4725fe54bbfa5fe7492c6a1bf1c6afebe" nocase ascii wide
                        $string6 = "Blank-c/BlankOBF" nocase ascii wide
                        $string7 = "BlankOBF v2: Obfuscates Python code to make it unreadable and hard to reverse" nocase ascii wide
                        $string8 = "from BlankOBFv2 import " nocase ascii wide
                        $string9 = "You managed to break through BlankOBF v2; Give yourself a pat on your back!" nocase ascii wide
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