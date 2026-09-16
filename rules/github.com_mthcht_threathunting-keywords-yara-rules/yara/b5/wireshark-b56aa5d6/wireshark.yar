rule wireshark
{
    meta:
        description = "Detection patterns for the tool 'wireshark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wireshark"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "bin/wireshark" nocase ascii wide
                        $string2 = /dl\.wireshark\.org/ nocase ascii wide
                        $string3 = "dumpcap -" nocase ascii wide
                        $string4 = "install tshark" nocase ascii wide
                        $string5 = "libwireshark16" nocase ascii wide
                        $string6 = "libwireshark-data" nocase ascii wide
                        $string7 = "libwireshark-dev" nocase ascii wide
                        $string8 = "libwiretap13" nocase ascii wide
                        $string9 = "--no-promiscuous-mode" nocase ascii wide
                        $string10 = "sharkd -a tcp:" nocase ascii wide
                        $string11 = /tshark\s.{0,100}\-i\s/ nocase ascii wide
                        $string12 = "tshark -f " nocase ascii wide
                        $string13 = "tshark -Q" nocase ascii wide
                        $string14 = "tshark -r " nocase ascii wide
                        $string15 = /tshark.{0,100}\.deb/ nocase ascii wide
                        $string16 = "Wireshark" nocase ascii wide
                        $string17 = /wireshark.{0,100}\.deb/ nocase ascii wide
                        $string18 = /Wireshark.{0,100}\.dmg/ nocase ascii wide
                        $string19 = /wireshark\-.{0,100}\.tar\.xz/ nocase ascii wide
                        $string20 = "wireshark-common" nocase ascii wide
                        $string21 = "wireshark-dev" nocase ascii wide
                        $string22 = "wireshark-gtk" nocase ascii wide
                        $string23 = "WiresharkPortable64" nocase ascii wide
                        $string24 = "wireshark-qt" nocase ascii wide
                        $string25 = /Wireshark\-win.{0,100}\.exe/ nocase ascii wide
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