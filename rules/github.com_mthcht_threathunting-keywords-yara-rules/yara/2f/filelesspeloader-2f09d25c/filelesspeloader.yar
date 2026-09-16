rule FilelessPELoader
{
    meta:
        description = "Detection patterns for the tool 'FilelessPELoader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FilelessPELoader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sAES_cryptor\.py\s/ nocase ascii wide
                        $string2 = "/FilelessPELoader" nocase ascii wide
                        $string3 = /\[\+\]\sGetPEFromRemoteServer/ nocase ascii wide
                        $string4 = /\\AES_cryptor\.py\s/ nocase ascii wide
                        $string5 = "4e2e5319f881c4a83bfeeeaf713beb1ee5ee4b19dff511abe8f05f9e2e1c3c55" nocase ascii wide
                        $string6 = "69a200568ae92a6eee56c9fcc170b088432871fb058c29459e7bf112a58d722f" nocase ascii wide
                        $string7 = "82277B35-D159-4B44-8D54-FB66EDD58D5C" nocase ascii wide
                        $string8 = "92804faaab2175dc501d73e814663058c78c0a042675a8937266357bcfb96c50" nocase ascii wide
                        $string9 = /AES_cryptor\.py\s/ nocase ascii wide
                        $string10 = "ca12dd05b0f8cff9da1c8e088808a8c6e3218eefa22c0d92469abda3888dab4d" nocase ascii wide
                        $string11 = /FilelessPELoader\.cpp/ nocase ascii wide
                        $string12 = /FilelessPELoader\.exe/ nocase ascii wide
                        $string13 = /FilelessPELoader\.sln/ nocase ascii wide
                        $string14 = /FilelessPELoader\.vcxproj/ nocase ascii wide
                        $string15 = "FilelessPELoader-main" nocase ascii wide
                        $string16 = /mimikatz\.exe/ nocase ascii wide
                        $string17 = /Trojan\:Win32\/TurtleLoader\./ nocase ascii wide
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