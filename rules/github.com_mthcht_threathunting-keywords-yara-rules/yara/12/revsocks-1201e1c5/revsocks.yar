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
                        $string10 = /\\revsocks\\.{0,1000}\.go/ nocase ascii wide
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

    condition:
        any of them
}