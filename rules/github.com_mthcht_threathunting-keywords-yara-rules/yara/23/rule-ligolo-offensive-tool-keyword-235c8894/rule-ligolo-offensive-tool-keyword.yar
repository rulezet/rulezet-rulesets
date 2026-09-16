rule rule_ligolo_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ligolo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ligolo"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ligolo_offensive_tool_keyword = /\s\-relayserver\s.{0,100}\:5555/ nocase ascii wide
                        $string2_ligolo_offensive_tool_keyword = /\/ligolo\.git/ nocase ascii wide
                        $string3_ligolo_offensive_tool_keyword = "/ligolo_agent"
                        $string4_ligolo_offensive_tool_keyword = /\/ligolo_agent\.exe/ nocase ascii wide
                        $string5_ligolo_offensive_tool_keyword = "/ligolo-ng" nocase ascii wide
                        $string6_ligolo_offensive_tool_keyword = "/ligolo-proxy" nocase ascii wide
                        $string7_ligolo_offensive_tool_keyword = "/ligolo-selfcert" nocase ascii wide
                        $string8_ligolo_offensive_tool_keyword = /\\ligolo_agent\.exe/ nocase ascii wide
                        $string9_ligolo_offensive_tool_keyword = /\\ligolo\-proxy/ nocase ascii wide
                        $string10_ligolo_offensive_tool_keyword = /127\.0\.0\.1\:1080/ nocase ascii wide
                        $string11_ligolo_offensive_tool_keyword = /127\.0\.0\.1\:5555/ nocase ascii wide
                        $string12_ligolo_offensive_tool_keyword = "bin/ligolo" nocase ascii wide
                        $string13_ligolo_offensive_tool_keyword = "bin/localrelay" nocase ascii wide
                        $string14_ligolo_offensive_tool_keyword = "cd ligolo" nocase ascii wide
                        $string15_ligolo_offensive_tool_keyword = "cmd/ligolo" nocase ascii wide
                        $string16_ligolo_offensive_tool_keyword = "cmd/localrelay" nocase ascii wide
                        $string17_ligolo_offensive_tool_keyword = "ip link set ligolo up"
                        $string18_ligolo_offensive_tool_keyword = /ligolo\.lan/
                        $string19_ligolo_offensive_tool_keyword = "ligolo_darwin"
                        $string20_ligolo_offensive_tool_keyword = "ligolo_linux"
                        $string21_ligolo_offensive_tool_keyword = /ligolo_windows.{0,100}\.exe/ nocase ascii wide
                        $string22_ligolo_offensive_tool_keyword = "ligolo-master" nocase ascii wide
                        $string23_ligolo_offensive_tool_keyword = "localrelay_linux_amd64"
                        $string24_ligolo_offensive_tool_keyword = /proxychains\snmap\s\-sT\s.{0,100}\s\-p\s.{0,100}\s\-Pn\s\-A/ nocase ascii wide
                        $string25_ligolo_offensive_tool_keyword = "proxychains rdesktop " nocase ascii wide
                        $string26_ligolo_offensive_tool_keyword = "src/ligolo" nocase ascii wide
                        $string27_ligolo_offensive_tool_keyword = "sysdream/ligolo" nocase ascii wide
                        $string28_ligolo_offensive_tool_keyword = "tools/ligolo" nocase ascii wide
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