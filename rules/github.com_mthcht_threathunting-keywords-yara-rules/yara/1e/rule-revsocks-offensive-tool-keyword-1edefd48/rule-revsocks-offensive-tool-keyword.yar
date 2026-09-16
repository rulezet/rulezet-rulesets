rule rule_revsocks_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'revsocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "revsocks"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_revsocks_offensive_tool_keyword = "/kost/revsocks/releases" nocase ascii wide
                        $string2_revsocks_offensive_tool_keyword = /\/out\:revsocks\.exe/
                        $string3_revsocks_offensive_tool_keyword = /\/revsocks\.exe/ nocase ascii wide
                        $string4_revsocks_offensive_tool_keyword = /\/revsocks\.exe/ nocase ascii wide
                        $string5_revsocks_offensive_tool_keyword = /\/revsocks\.git/ nocase ascii wide
                        $string6_revsocks_offensive_tool_keyword = /\/revsocks\.git/ nocase ascii wide
                        $string7_revsocks_offensive_tool_keyword = /\\InventoryApplicationFile\\revsocks_windows/ nocase ascii wide
                        $string8_revsocks_offensive_tool_keyword = /\\revsocks\.exe/ nocase ascii wide
                        $string9_revsocks_offensive_tool_keyword = /\\revsocks\.exe/ nocase ascii wide
                        $string10_revsocks_offensive_tool_keyword = /\\revsocks\\.{0,100}\.go/ nocase ascii wide
                        $string11_revsocks_offensive_tool_keyword = /\\revsocks\\make\.bat/ nocase ascii wide
                        $string12_revsocks_offensive_tool_keyword = /\\revsocks\-master\\/ nocase ascii wide
                        $string13_revsocks_offensive_tool_keyword = "Cannot send REVSOCKS_NORMAL handshake!" nocase ascii wide
                        $string14_revsocks_offensive_tool_keyword = "emilarner/revsocks" nocase ascii wide
                        $string15_revsocks_offensive_tool_keyword = "kost/revsocks" nocase ascii wide
                        $string16_revsocks_offensive_tool_keyword = "revsocks - reverse socks5 server/client" nocase ascii wide
                        $string17_revsocks_offensive_tool_keyword = "revsocks -connect" nocase ascii wide
                        $string18_revsocks_offensive_tool_keyword = "revsocks -dns" nocase ascii wide
                        $string19_revsocks_offensive_tool_keyword = "revsocks -listen" nocase ascii wide
                        $string20_revsocks_offensive_tool_keyword = "revsocks_darwin_amd64"
                        $string21_revsocks_offensive_tool_keyword = "revsocks_freebsd_386" nocase ascii wide
                        $string22_revsocks_offensive_tool_keyword = "revsocks_freebsd_amd64" nocase ascii wide
                        $string23_revsocks_offensive_tool_keyword = "revsocks_freebsd_arm" nocase ascii wide
                        $string24_revsocks_offensive_tool_keyword = "revsocks_linux_386"
                        $string25_revsocks_offensive_tool_keyword = "revsocks_linux_amd64"
                        $string26_revsocks_offensive_tool_keyword = "revsocks_linux_arm"
                        $string27_revsocks_offensive_tool_keyword = "revsocks_linux_mips"
                        $string28_revsocks_offensive_tool_keyword = "revsocks_linux_mipsle"
                        $string29_revsocks_offensive_tool_keyword = "revsocks_linux_s390x"
                        $string30_revsocks_offensive_tool_keyword = "revsocks_netbsd_386" nocase ascii wide
                        $string31_revsocks_offensive_tool_keyword = "revsocks_netbsd_amd64" nocase ascii wide
                        $string32_revsocks_offensive_tool_keyword = "revsocks_netbsd_arm" nocase ascii wide
                        $string33_revsocks_offensive_tool_keyword = "revsocks_openbsd_386" nocase ascii wide
                        $string34_revsocks_offensive_tool_keyword = "revsocks_openbsd_amd64" nocase ascii wide
                        $string35_revsocks_offensive_tool_keyword = /revsocks_windows_386\.exe/ nocase ascii wide
                        $string36_revsocks_offensive_tool_keyword = /revsocks_windows_amd64\.exe/ nocase ascii wide
                        $string37_revsocks_offensive_tool_keyword = /revsocksserver\.h/ nocase ascii wide
                        $string38_revsocks_offensive_tool_keyword = "starting RevSocksServer: " nocase ascii wide
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