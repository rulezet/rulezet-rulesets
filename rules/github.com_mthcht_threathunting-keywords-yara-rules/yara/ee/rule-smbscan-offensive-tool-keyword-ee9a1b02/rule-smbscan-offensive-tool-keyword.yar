rule rule_smbscan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'smbscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smbscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_smbscan_offensive_tool_keyword = /\sCRITICAL\]\sSuspicous\sfile\:\s\\\\/ nocase ascii wide
                        $string2_smbscan_offensive_tool_keyword = /\ssmbscan\.py\s/ nocase ascii wide
                        $string3_smbscan_offensive_tool_keyword = /\/smbscan\-.{0,100}\.csv/
                        $string4_smbscan_offensive_tool_keyword = /\/smbscan\-.{0,100}\.log/
                        $string5_smbscan_offensive_tool_keyword = /\/smbscan\.git/ nocase ascii wide
                        $string6_smbscan_offensive_tool_keyword = /\/smbscan\.py/ nocase ascii wide
                        $string7_smbscan_offensive_tool_keyword = /\\smbscan\-.{0,100}\.csv/ nocase ascii wide
                        $string8_smbscan_offensive_tool_keyword = /\\smbscan\-.{0,100}\.log/ nocase ascii wide
                        $string9_smbscan_offensive_tool_keyword = /\\smbscan\.py/ nocase ascii wide
                        $string10_smbscan_offensive_tool_keyword = "a4d92518de887211fcc6d0f0c011336140fa14d69a505223947a088cec3a9c0f" nocase ascii wide
                        $string11_smbscan_offensive_tool_keyword = "dc9978d7-6299-4c5a-a22d-a039cdc716ea" nocase ascii wide
                        $string12_smbscan_offensive_tool_keyword = /impacket\.smbconnection\.SMBConnection/ nocase ascii wide
                        $string13_smbscan_offensive_tool_keyword = "jeffhacks/smbscan" nocase ascii wide
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