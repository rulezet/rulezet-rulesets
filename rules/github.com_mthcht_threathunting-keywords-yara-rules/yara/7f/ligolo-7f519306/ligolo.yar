rule ligolo
{
    meta:
        description = "Detection patterns for the tool 'ligolo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ligolo"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-relayserver\s.{0,100}\:5555/ nocase ascii wide
                        $string2 = /\/ligolo\.git/ nocase ascii wide
                        $string3 = "/ligolo_agent"
                        $string4 = /\/ligolo_agent\.exe/ nocase ascii wide
                        $string5 = "/ligolo-ng" nocase ascii wide
                        $string6 = "/ligolo-proxy" nocase ascii wide
                        $string7 = "/ligolo-selfcert" nocase ascii wide
                        $string8 = /\\ligolo_agent\.exe/ nocase ascii wide
                        $string9 = /\\ligolo\-proxy/ nocase ascii wide
                        $string10 = /127\.0\.0\.1\:1080/ nocase ascii wide
                        $string11 = /127\.0\.0\.1\:5555/ nocase ascii wide
                        $string12 = "bin/ligolo" nocase ascii wide
                        $string13 = "bin/localrelay" nocase ascii wide
                        $string14 = "cd ligolo" nocase ascii wide
                        $string15 = "cmd/ligolo" nocase ascii wide
                        $string16 = "cmd/localrelay" nocase ascii wide
                        $string17 = "ip link set ligolo up"
                        $string18 = /ligolo\.lan/
                        $string19 = "ligolo_darwin"
                        $string20 = "ligolo_linux"
                        $string21 = /ligolo_windows.{0,100}\.exe/ nocase ascii wide
                        $string22 = "ligolo-master" nocase ascii wide
                        $string23 = "localrelay_linux_amd64"
                        $string24 = /proxychains\snmap\s\-sT\s.{0,100}\s\-p\s.{0,100}\s\-Pn\s\-A/ nocase ascii wide
                        $string25 = "proxychains rdesktop " nocase ascii wide
                        $string26 = "src/ligolo" nocase ascii wide
                        $string27 = "sysdream/ligolo" nocase ascii wide
                        $string28 = "tools/ligolo" nocase ascii wide
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