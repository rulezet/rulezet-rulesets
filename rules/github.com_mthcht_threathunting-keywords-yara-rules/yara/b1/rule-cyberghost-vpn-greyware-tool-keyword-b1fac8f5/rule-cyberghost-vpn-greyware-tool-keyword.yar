rule rule_CyberGhost_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CyberGhost VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CyberGhost VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_CyberGhost_VPN_greyware_tool_keyword = /\\AppData\\Local\\CyberGhost/ nocase ascii wide
                        $string2_CyberGhost_VPN_greyware_tool_keyword = /\\Applications\\VPN\\Data\\OpenVPN\\/ nocase ascii wide
                        $string3_CyberGhost_VPN_greyware_tool_keyword = /\\Applications\\VPN\\tunnel\.dll/ nocase ascii wide
                        $string4_CyberGhost_VPN_greyware_tool_keyword = /\\Applications\\VPN\\wireguard\.dll/ nocase ascii wide
                        $string5_CyberGhost_VPN_greyware_tool_keyword = /\\CyberGhost\s6\.lnk/ nocase ascii wide
                        $string6_CyberGhost_VPN_greyware_tool_keyword = /\\CyberGhost\s7\.lnk/ nocase ascii wide
                        $string7_CyberGhost_VPN_greyware_tool_keyword = /\\CyberGhost\s8\.lnk/ nocase ascii wide
                        $string8_CyberGhost_VPN_greyware_tool_keyword = /\\CyberGhost\.VPN\..{0,100}\.exe/ nocase ascii wide
                        $string9_CyberGhost_VPN_greyware_tool_keyword = /\\CyberGhost\-WireGuard\-1\.conf/ nocase ascii wide
                        $string10_CyberGhost_VPN_greyware_tool_keyword = /\\Dashboard\.exe\.config/ nocase ascii wide
                        $string11_CyberGhost_VPN_greyware_tool_keyword = /\\Program\sFiles\\CyberGhost/ nocase ascii wide
                        $string12_CyberGhost_VPN_greyware_tool_keyword = /\\Windows\\Temp\\.{0,100}\\wireguard\.sys/ nocase ascii wide
                        $string13_CyberGhost_VPN_greyware_tool_keyword = ">CyberGhost 6 Installer<" nocase ascii wide
                        $string14_CyberGhost_VPN_greyware_tool_keyword = ">CyberGhost 7 Installer<" nocase ascii wide
                        $string15_CyberGhost_VPN_greyware_tool_keyword = ">CyberGhost 8 Installer<" nocase ascii wide
                        $string16_CyberGhost_VPN_greyware_tool_keyword = /api\.cyberghostvpn\.com/ nocase ascii wide
                        $string17_CyberGhost_VPN_greyware_tool_keyword = "CyberGhost 6 Service" nocase ascii wide
                        $string18_CyberGhost_VPN_greyware_tool_keyword = "CyberGhost 7 Service" nocase ascii wide
                        $string19_CyberGhost_VPN_greyware_tool_keyword = "CyberGhost 8 Service" nocase ascii wide
                        $string20_CyberGhost_VPN_greyware_tool_keyword = /CyberGhost\sS\.R\.L\./ nocase ascii wide
                        $string21_CyberGhost_VPN_greyware_tool_keyword = "CyberGhost Tunnel Client:" nocase ascii wide
                        $string22_CyberGhost_VPN_greyware_tool_keyword = /cyberghost.{0,100}\\Dashboard\.exe/ nocase ascii wide
                        $string23_CyberGhost_VPN_greyware_tool_keyword = /cyberghost.{0,100}\\Dashboard\.Service\.exe/ nocase ascii wide
                        $string24_CyberGhost_VPN_greyware_tool_keyword = /cyberghost.{0,100}\\wyUpdate\.exe/ nocase ascii wide
                        $string25_CyberGhost_VPN_greyware_tool_keyword = /CyberGhost\.Browser\.dll/ nocase ascii wide
                        $string26_CyberGhost_VPN_greyware_tool_keyword = /CyberGhost\.exe/ nocase ascii wide
                        $string27_CyberGhost_VPN_greyware_tool_keyword = /CyberGhost\.resources\.dll/ nocase ascii wide
                        $string28_CyberGhost_VPN_greyware_tool_keyword = /CyberGhost\.Service\.exe/ nocase ascii wide
                        $string29_CyberGhost_VPN_greyware_tool_keyword = /CyberGhost\.Service\.InstallLog/ nocase ascii wide
                        $string30_CyberGhost_VPN_greyware_tool_keyword = /CyberGhost\.Service\.pdb/ nocase ascii wide
                        $string31_CyberGhost_VPN_greyware_tool_keyword = /CyberGhost\.VPNServices\.dll/ nocase ascii wide
                        $string32_CyberGhost_VPN_greyware_tool_keyword = "CyberGhost6Service" nocase ascii wide
                        $string33_CyberGhost_VPN_greyware_tool_keyword = "CyberGhost7Service" nocase ascii wide
                        $string34_CyberGhost_VPN_greyware_tool_keyword = "CyberGhost8Service" nocase ascii wide
                        $string35_CyberGhost_VPN_greyware_tool_keyword = /CyberGhostTunnel\$CyberGhost\-WireGuard\-1/ nocase ascii wide
                        $string36_CyberGhost_VPN_greyware_tool_keyword = /CyberGhostVPNSetup\.exe/ nocase ascii wide
                        $string37_CyberGhost_VPN_greyware_tool_keyword = /CyberGhost\-WireGuard\-1\.conf/ nocase ascii wide
                        $string38_CyberGhost_VPN_greyware_tool_keyword = /download\.cyberghostvpn\.com/ nocase ascii wide
                        $string39_CyberGhost_VPN_greyware_tool_keyword = /feedback\.cyberghostvpn\.com/ nocase ascii wide
                        $string40_CyberGhost_VPN_greyware_tool_keyword = "ffbkglfijbcbgblgflchnbphjdllaogb" nocase ascii wide
                        $string41_CyberGhost_VPN_greyware_tool_keyword = /payment\.cyberghostvpn\.com/ nocase ascii wide
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