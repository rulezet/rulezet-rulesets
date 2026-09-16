rule RPC_Backdoor
{
    meta:
        description = "Detection patterns for the tool 'RPC-Backdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RPC-Backdoor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-pipename\s.{0,100}\\\\pipe\\\\atctl\\/ nocase ascii wide
                        $string2 = /\/RPC\-Backdoor\.git/ nocase ascii wide
                        $string3 = /\/RPC\-Backdoor_v1\.0\.7z/ nocase ascii wide
                        $string4 = /\/RPC\-Backdoor_v1\.0\.zip/ nocase ascii wide
                        $string5 = /\\RPC\sBackdoor\.sln/ nocase ascii wide
                        $string6 = /\\RPC\-Backdoor\\/ nocase ascii wide
                        $string7 = /\\RPC\-Backdoor_v1\.0\.7z/ nocase ascii wide
                        $string8 = /\\RPC\-Backdoor_v1\.0\.zip/ nocase ascii wide
                        $string9 = /\\RPC\-Backdoor\-main/ nocase ascii wide
                        $string10 = "0ABB9F2A-6913-4174-9431-851F9D3E94B4" nocase ascii wide
                        $string11 = "3C21F82B-B958-457A-82BB-B8A795316D3D" nocase ascii wide
                        $string12 = "6299009a4d05609f3960b17f3714579cd3fa4e85c2dbab240672301884fd89d5" nocase ascii wide
                        $string13 = "6536EBEC-014E-4D6B-97BE-223137694CA8" nocase ascii wide
                        $string14 = "758DB128-9123-4E1B-A6C3-47323714123A" nocase ascii wide
                        $string15 = "758DB129-9123-4E1B-A6C3-47323714123A" nocase ascii wide
                        $string16 = "7aa8e56e132d653609ccc17d76b630500443bc7b4b9a3eeba8359151d3db5961" nocase ascii wide
                        $string17 = "8558952E-C76B-4976-949F-76A977DA7F8A" nocase ascii wide
                        $string18 = "ca2aa2a0ef687163b261bba61c0b55033e9c4080bfb889e48b7e4664a2af91ed" nocase ascii wide
                        $string19 = "eladshamir/RPC-Backdoor" nocase ascii wide
                        $string20 = "net user hax0r /add" nocase ascii wide
                        $string21 = /RpcSharpClient\.exe\s\-\-protocol\snamedpipe\s/ nocase ascii wide
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