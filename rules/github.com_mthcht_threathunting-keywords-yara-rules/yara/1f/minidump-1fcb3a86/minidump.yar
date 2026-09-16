rule MiniDump
{
    meta:
        description = "Detection patterns for the tool 'MiniDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MiniDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\(Program\.MiniDump\sminidump/ nocase ascii wide
                        $string2 = /\/MiniDump\.git/ nocase ascii wide
                        $string3 = /\/MiniDump\-main\.zip/ nocase ascii wide
                        $string4 = /\\\\MiniDump\\\\Decryptor\\\\Credman/ nocase ascii wide
                        $string5 = /\\\\MiniDump\\\\Decryptor\\\\KerberosSessions/ nocase ascii wide
                        $string6 = /\\\\MiniDump\\\\Decryptor\\\\LogonSessions/ nocase ascii wide
                        $string7 = /\\\\windows\\\\temp\\\\lsass\.dmp/ nocase ascii wide
                        $string8 = /\\Minidump\.exe\sc\:\\/ nocase ascii wide
                        $string9 = /\\Minidump\.exe\\"\sc\:\\/ nocase ascii wide
                        $string10 = /\\MiniDump\-main/ nocase ascii wide
                        $string11 = "b2383e05411ba4a0e24dbfc67e5e4e1ddeae37acdf1137bccbf8d190d13c78a5" nocase ascii wide
                        $string12 = "BA1F3992-9654-4424-A0CC-26158FDFBF74" nocase ascii wide
                        $string13 = "cube0x0/MiniDump" nocase ascii wide
                        $string14 = "f038fdbc3ed50ebbf1ebc1c814836bcf93b4c149e5856ccf9b5400da8a974117" nocase ascii wide
                        $string15 = "lsadecryptor_lsa_decryptor" nocase ascii wide
                        $string16 = /minidump\.lsakeys/ nocase ascii wide
                        $string17 = /procdump64\.exe\s\-ma\slsass\.exe/ nocase ascii wide
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