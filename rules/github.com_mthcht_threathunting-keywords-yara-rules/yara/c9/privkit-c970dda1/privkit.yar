rule PrivKit
{
    meta:
        description = "Detection patterns for the tool 'PrivKit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrivKit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PrivKit\.git/ nocase ascii wide
                        $string2 = "/PrivKit/" nocase ascii wide
                        $string3 = /\\modifiableautorun\.o/ nocase ascii wide
                        $string4 = /\\PrivKit\\/ nocase ascii wide
                        $string5 = /\\tokenprivileges\.c/ nocase ascii wide
                        $string6 = /\\tokenprivileges\.o/ nocase ascii wide
                        $string7 = /\\unquotedsvcpath\.o/ nocase ascii wide
                        $string8 = /alwaysinstallelevated\.c/ nocase ascii wide
                        $string9 = /alwaysinstallelevated\.o/ nocase ascii wide
                        $string10 = /\-c\scredentialmanager\.c\s\-o\scredentialmanager\.o/ nocase ascii wide
                        $string11 = /\-c\smodifiableautorun\.c\s\-o\smodifiableautorun\.o/ nocase ascii wide
                        $string12 = /\-c\stokenprivileges\.c\s\-o\stokenprivileges\.o/ nocase ascii wide
                        $string13 = /\-c\sunquotedsvcpath\.c\s\-o\sunquotedsvcpath\.o/ nocase ascii wide
                        $string14 = /hijackablepath\.c/ nocase ascii wide
                        $string15 = /hijackablepath\.o/ nocase ascii wide
                        $string16 = /inline\-execute\s.{0,100}tokenprivileges\.o/ nocase ascii wide
                        $string17 = "Priv Esc Check Bof" nocase ascii wide
                        $string18 = /privcheck\.cna/ nocase ascii wide
                        $string19 = "privcheck32" nocase ascii wide
                        $string20 = "PrivKit32" nocase ascii wide
                        $string21 = "PrivKit-main" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}