rule aircrack
{
    meta:
        description = "Detection patterns for the tool 'aircrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aircrack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-r\sairolib\-db\s\/root\/wpa\.cap/ nocase ascii wide
                        $string2 = "airbase-ng -" nocase ascii wide
                        $string3 = /aircrack\.txt/ nocase ascii wide
                        $string4 = "Aircrack-ng" nocase ascii wide
                        $string5 = "aircrack-ptw-" nocase ascii wide
                        $string6 = "airdecap-ng -" nocase ascii wide
                        $string7 = "aireplay-ng -" nocase ascii wide
                        $string8 = "airgraph-ng -" nocase ascii wide
                        $string9 = "airodump-ng " nocase ascii wide
                        $string10 = "airodump-ng " nocase ascii wide
                        $string11 = "airolib-ng airolib-db" nocase ascii wide
                        $string12 = "airserv-ng -" nocase ascii wide
                        $string13 = "airtun-ng -a " nocase ascii wide
                        $string14 = "besside-ng -W -v " nocase ascii wide
                        $string15 = /easside\-ng\s\-.{0,100}\s\-s\s127\.0\.0\.1/ nocase ascii wide
                        $string16 = "makeivs-ng -b " nocase ascii wide
                        $string17 = "wesside-ng -" nocase ascii wide
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