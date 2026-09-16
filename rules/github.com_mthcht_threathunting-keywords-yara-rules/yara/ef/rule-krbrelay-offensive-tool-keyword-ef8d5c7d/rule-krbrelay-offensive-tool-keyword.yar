rule rule_KrbRelay_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KrbRelay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KrbRelay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KrbRelay_offensive_tool_keyword = /\sasktgt\s\/user\:\{0\}\s\/certificate\:\{1\}\s\/password\:\\"\{2\}\\"\s/ nocase ascii wide
                        $string2_KrbRelay_offensive_tool_keyword = /\s\-spn\scifs.{0,100}\s\-session\s.{0,100}\s\-clsid\s.{0,100}\s\-secrets/ nocase ascii wide
                        $string3_KrbRelay_offensive_tool_keyword = /\/CheckPort\.exe/ nocase ascii wide
                        $string4_KrbRelay_offensive_tool_keyword = "/KrbRelay" nocase ascii wide
                        $string5_KrbRelay_offensive_tool_keyword = /\/KrbRelay\.exe/ nocase ascii wide
                        $string6_KrbRelay_offensive_tool_keyword = /\\KrbRelay\.exe/ nocase ascii wide
                        $string7_KrbRelay_offensive_tool_keyword = ">KrbRelay<" nocase ascii wide
                        $string8_KrbRelay_offensive_tool_keyword = /CheckPort\.csproj/ nocase ascii wide
                        $string9_KrbRelay_offensive_tool_keyword = "KrbRelay by @Cube0x0" nocase ascii wide
                        $string10_KrbRelay_offensive_tool_keyword = /KrbRelay.{0,100}misc/ nocase ascii wide
                        $string11_KrbRelay_offensive_tool_keyword = /KrbRelay.{0,100}smb/ nocase ascii wide
                        $string12_KrbRelay_offensive_tool_keyword = /KrbRelay.{0,100}spoofing/ nocase ascii wide
                        $string13_KrbRelay_offensive_tool_keyword = /KrbRelay\.csproj/ nocase ascii wide
                        $string14_KrbRelay_offensive_tool_keyword = /KrbRelay\.exe\s/ nocase ascii wide
                        $string15_KrbRelay_offensive_tool_keyword = /KrbRelay\.exe/ nocase ascii wide
                        $string16_KrbRelay_offensive_tool_keyword = /KrbRelay\.sln/ nocase ascii wide
                        $string17_KrbRelay_offensive_tool_keyword = /\-llmnr\s\-spn\s\'.{0,100}cifs.{0,100}\s\-secrets/ nocase ascii wide
                        $string18_KrbRelay_offensive_tool_keyword = /OleViewDotNet\.psd1/ nocase ascii wide
                        $string19_KrbRelay_offensive_tool_keyword = /\-spn\s.{0,100}\s\-clsid\s.{0,100}\s\-shadowcred/ nocase ascii wide
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