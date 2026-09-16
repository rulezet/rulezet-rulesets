rule localxpose
{
    meta:
        description = "Detection patterns for the tool 'localxpose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localxpose"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.loclx\.io\:/ nocase ascii wide
                        $string2 = /\/.{0,100}\.loclx\.io/ nocase ascii wide
                        $string3 = /\/loclx\.exe/ nocase ascii wide
                        $string4 = /\/loclx\-windows\-amd64\.zip/ nocase ascii wide
                        $string5 = /\\loclx\.exe/ nocase ascii wide
                        $string6 = /\\loclx\-windows\-amd64\.zip/ nocase ascii wide
                        $string7 = "17a9356024d2fa2ae8f327fc5babc10eb859e0c433e768cd03a50dd9c7880601" nocase ascii wide
                        $string8 = "33ab2fa30777211450e30c21c45803cdf076cb991f05691bd60aef97a8183e04" nocase ascii wide
                        $string9 = /api\.localxpose\.io/ nocase ascii wide
                        $string10 = "brew install --cask localxpose" nocase ascii wide
                        $string11 = "cd1978742a4afdbaaa15bf712d5c90bef4144caa99024df98f6a9ad58043ae85" nocase ascii wide
                        $string12 = "choco install localxpose" nocase ascii wide
                        $string13 = /https\:\/\/localxpose\.io\/download/ nocase ascii wide
                        $string14 = "localxpose/localxpose" nocase ascii wide
                        $string15 = "loclx tunnel config " nocase ascii wide
                        $string16 = "loclx tunnel http " nocase ascii wide
                        $string17 = "loclx tunnel tcp " nocase ascii wide
                        $string18 = "loclx tunnel tls " nocase ascii wide
                        $string19 = "loclx tunnel udp " nocase ascii wide
                        $string20 = /loclx\.exe\stunnel\shttp\s/ nocase ascii wide
                        $string21 = /loclx\.exe\stunnel\stcp\s/ nocase ascii wide
                        $string22 = /loclx\.exe\stunnel\stls\s/ nocase ascii wide
                        $string23 = /loclx\.exe\stunnel\sudp\s/ nocase ascii wide
                        $string24 = /loclx\-client\.s3\.amazonaws\.com/ nocase ascii wide
                        $string25 = "npm install localxpose" nocase ascii wide
                        $string26 = "snap install localxpose" nocase ascii wide
                        $string27 = "yarn add localxpose" nocase ascii wide
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