rule revsocks
{
    meta:
        description = "Detection patterns for the tool 'revsocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "revsocks"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/kost/revsocks/releases" nocase ascii wide
                        $string2 = /\/out\:revsocks\.exe/
                        $string3 = /\/revsocks\.exe/ nocase ascii wide
                        $string4 = /\/revsocks\.exe/ nocase ascii wide
                        $string5 = /\/revsocks\.git/ nocase ascii wide
                        $string6 = /\/revsocks\.git/ nocase ascii wide
                        $string7 = /\\InventoryApplicationFile\\revsocks_windows/ nocase ascii wide
                        $string8 = /\\revsocks\.exe/ nocase ascii wide
                        $string9 = /\\revsocks\.exe/ nocase ascii wide
                        $string10 = /\\revsocks\\.{0,100}\.go/ nocase ascii wide
                        $string11 = /\\revsocks\\make\.bat/ nocase ascii wide
                        $string12 = /\\revsocks\-master\\/ nocase ascii wide
                        $string13 = "Cannot send REVSOCKS_NORMAL handshake!" nocase ascii wide
                        $string14 = "emilarner/revsocks" nocase ascii wide
                        $string15 = "kost/revsocks" nocase ascii wide
                        $string16 = "revsocks - reverse socks5 server/client" nocase ascii wide
                        $string17 = "revsocks -connect" nocase ascii wide
                        $string18 = "revsocks -dns" nocase ascii wide
                        $string19 = "revsocks -listen" nocase ascii wide
                        $string20 = "revsocks_darwin_amd64"
                        $string21 = "revsocks_freebsd_386" nocase ascii wide
                        $string22 = "revsocks_freebsd_amd64" nocase ascii wide
                        $string23 = "revsocks_freebsd_arm" nocase ascii wide
                        $string24 = "revsocks_linux_386"
                        $string25 = "revsocks_linux_amd64"
                        $string26 = "revsocks_linux_arm"
                        $string27 = "revsocks_linux_mips"
                        $string28 = "revsocks_linux_mipsle"
                        $string29 = "revsocks_linux_s390x"
                        $string30 = "revsocks_netbsd_386" nocase ascii wide
                        $string31 = "revsocks_netbsd_amd64" nocase ascii wide
                        $string32 = "revsocks_netbsd_arm" nocase ascii wide
                        $string33 = "revsocks_openbsd_386" nocase ascii wide
                        $string34 = "revsocks_openbsd_amd64" nocase ascii wide
                        $string35 = /revsocks_windows_386\.exe/ nocase ascii wide
                        $string36 = /revsocks_windows_amd64\.exe/ nocase ascii wide
                        $string37 = /revsocksserver\.h/ nocase ascii wide
                        $string38 = "starting RevSocksServer: " nocase ascii wide
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