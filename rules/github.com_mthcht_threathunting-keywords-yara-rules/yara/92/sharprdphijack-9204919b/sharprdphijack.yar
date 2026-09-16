rule SharpRDPHijack
{
    meta:
        description = "Detection patterns for the tool 'SharpRDPHijack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRDPHijack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "- RDP Session Hijack" nocase ascii wide
                        $string2 = " SharpRDPHijack" nocase ascii wide
                        $string3 = /\.exe\s\-\-session\=2\s\-\-shadow\s\-\-console/ nocase ascii wide
                        $string4 = "/SharpRDPHijack" nocase ascii wide
                        $string5 = /\-\\nSharp\sRDP\sHijack\\n\-/ nocase ascii wide
                        $string6 = /\\SharpRDPHijack/ nocase ascii wide
                        $string7 = "622f3304b381b2f3a99567be78a668e21c1c6a405320da78a2af32addbc29d88" nocase ascii wide
                        $string8 = "Benjamin Delpy - RDP Session Tradecraft" nocase ascii wide
                        $string9 = /blog\.gentilkiwi\.com\/securite\/vol\-de\-session\-rdp/ nocase ascii wide
                        $string10 = "Hijack Remote Desktop session #4 with knowledge of the logged-on user" nocase ascii wide
                        $string11 = /https\:\/\/www\.exploit\-db\.com\/exploits\/41607/ nocase ascii wide
                        $string12 = /Impersonate\sNT\sAUTHORITY\\\\SYSTEM\sto\shijack\ssession/ nocase ascii wide
                        $string13 = /SharpRDPHijack\.cs/ nocase ascii wide
                        $string14 = /SharpRDPHijack\.exe/ nocase ascii wide
                        $string15 = "SharpRDPHijack-master" nocase ascii wide
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