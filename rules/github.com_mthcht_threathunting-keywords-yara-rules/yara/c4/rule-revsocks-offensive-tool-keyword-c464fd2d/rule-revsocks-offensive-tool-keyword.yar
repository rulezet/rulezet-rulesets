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
                        $string10_revsocks_offensive_tool_keyword = /\\revsocks\\.{0,1000}\.go/ nocase ascii wide
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

    condition:
        any of them
}