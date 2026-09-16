rule Voidgate
{
    meta:
        description = "Detection patterns for the tool 'Voidgate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Voidgate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Voidgate\.exe/ nocase ascii wide
                        $string2 = /\/Voidgate\.git/ nocase ascii wide
                        $string3 = /\\Voidgate\.cpp/ nocase ascii wide
                        $string4 = /\\Voidgate\.exe/ nocase ascii wide
                        $string5 = /\\voidgate\-master\\/ nocase ascii wide
                        $string6 = /\\Windows\\temp\\payload\.bin/ nocase ascii wide
                        $string7 = "15bdbbebff7a58257d1cd0ade5d76877259c2b3152508f1b2534a6fcab89cb38" nocase ascii wide
                        $string8 = "39fa3b4151fd83044106b63e95a820f4f1d769714d4f73369dba7a2187e0918b" nocase ascii wide
                        $string9 = "bba575ec-0c7f-42e1-9b59-b7c9cca522ba" nocase ascii wide
                        $string10 = "c06bb3f0-cbdc-4384-84cf-21b7fe6dfe01" nocase ascii wide
                        $string11 = "vxCrypt0r/Voidgate" nocase ascii wide
                        $string12 = /XorEncryptPayload\.cpp/ nocase ascii wide
                        $string13 = /XorEncryptPayload\.exe/ nocase ascii wide
                        $string14 = /XorEncryptPayload\.vcxproj/ nocase ascii wide
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