rule DocPlz
{
    meta:
        description = "Detection patterns for the tool 'DocPlz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DocPlz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sComunicationC2\.cpp/ nocase ascii wide
                        $string2 = /\/ComunicationC2\.cpp/ nocase ascii wide
                        $string3 = /\/DocPlz\.git/ nocase ascii wide
                        $string4 = /\/DocsPLZ\.cpp/ nocase ascii wide
                        $string5 = /\/DocsPLZ\.exe/ nocase ascii wide
                        $string6 = /\/ServerC2\.cpp/ nocase ascii wide
                        $string7 = /\/ServerC2\.exe/ nocase ascii wide
                        $string8 = /\\ComunicationC2\.cpp/ nocase ascii wide
                        $string9 = /\\DocsPLZ\.cpp/ nocase ascii wide
                        $string10 = /\\DocsPLZ\.exe/ nocase ascii wide
                        $string11 = /\\Persistence\.exe/ nocase ascii wide
                        $string12 = /\\ServerC2\.cpp/ nocase ascii wide
                        $string13 = /\\ServerC2\.exe/ nocase ascii wide
                        $string14 = /\\ServerC2\\ServerC2\./ nocase ascii wide
                        $string15 = "4C3B106C-8782-4374-9459-851749072123" nocase ascii wide
                        $string16 = "5E0812A9-C727-44F3-A2E3-8286CDC3ED4F" nocase ascii wide
                        $string17 = /DocPlz\-main\.zip/ nocase ascii wide
                        $string18 = /DocsPLZ\\DocsPLZ\./ nocase ascii wide
                        $string19 = "TheD1rkMtr/DocPlz" nocase ascii wide
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