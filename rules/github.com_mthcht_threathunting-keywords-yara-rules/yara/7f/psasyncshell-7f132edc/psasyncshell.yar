rule PSAsyncShell
{
    meta:
        description = "Detection patterns for the tool 'PSAsyncShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSAsyncShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPSAsyncShell\.ps1/ nocase ascii wide
                        $string2 = /\sPSAsyncShell\.sh/ nocase ascii wide
                        $string3 = /\/PSAsyncShell\.git/ nocase ascii wide
                        $string4 = /\/PSAsyncShell\.ps1/ nocase ascii wide
                        $string5 = /\/PSAsyncShell\.sh/ nocase ascii wide
                        $string6 = "/PSAsyncShell-main" nocase ascii wide
                        $string7 = /\[\+\]\sPSAsyncShell\sOK\!/ nocase ascii wide
                        $string8 = /\\PSAsyncShell\.ps1/ nocase ascii wide
                        $string9 = /\\PSAsyncShell\.sh/ nocase ascii wide
                        $string10 = /\\PSAsyncShell\-main/ nocase ascii wide
                        $string11 = "c88583cefd0d79a7db5a22290081218d5d9e2ce83de1ca17b8242f7fc74b2535" nocase ascii wide
                        $string12 = "cc49a6056b1f2216c0986cd16b01d2fb5bc03664a2818a5ce3ecdc6a3132707c" nocase ascii wide
                        $string13 = "JoelGMSec/PSAsyncShell" nocase ascii wide
                        $string14 = "PSAsyncShell by @JoelGMSec" nocase ascii wide
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