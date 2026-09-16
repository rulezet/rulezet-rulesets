rule CyberGhost_VPN
{
    meta:
        description = "Detection patterns for the tool 'CyberGhost VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CyberGhost VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\AppData\\Local\\CyberGhost/ nocase ascii wide
                        $string2 = /\\Applications\\VPN\\Data\\OpenVPN\\/ nocase ascii wide
                        $string3 = /\\Applications\\VPN\\tunnel\.dll/ nocase ascii wide
                        $string4 = /\\Applications\\VPN\\wireguard\.dll/ nocase ascii wide
                        $string5 = /\\CyberGhost\s6\.lnk/ nocase ascii wide
                        $string6 = /\\CyberGhost\s7\.lnk/ nocase ascii wide
                        $string7 = /\\CyberGhost\s8\.lnk/ nocase ascii wide
                        $string8 = /\\CyberGhost\.VPN\..{0,1000}\.exe/ nocase ascii wide
                        $string9 = /\\CyberGhost\-WireGuard\-1\.conf/ nocase ascii wide
                        $string10 = /\\Dashboard\.exe\.config/ nocase ascii wide
                        $string11 = /\\Program\sFiles\\CyberGhost/ nocase ascii wide
                        $string12 = /\\Windows\\Temp\\.{0,1000}\\wireguard\.sys/ nocase ascii wide
                        $string13 = ">CyberGhost 6 Installer<" nocase ascii wide
                        $string14 = ">CyberGhost 7 Installer<" nocase ascii wide
                        $string15 = ">CyberGhost 8 Installer<" nocase ascii wide
                        $string16 = /api\.cyberghostvpn\.com/ nocase ascii wide
                        $string17 = "CyberGhost 6 Service" nocase ascii wide
                        $string18 = "CyberGhost 7 Service" nocase ascii wide
                        $string19 = "CyberGhost 8 Service" nocase ascii wide
                        $string20 = /CyberGhost\sS\.R\.L\./ nocase ascii wide
                        $string21 = "CyberGhost Tunnel Client:" nocase ascii wide
                        $string22 = /cyberghost.{0,1000}\\Dashboard\.exe/ nocase ascii wide
                        $string23 = /cyberghost.{0,1000}\\Dashboard\.Service\.exe/ nocase ascii wide
                        $string24 = /cyberghost.{0,1000}\\wyUpdate\.exe/ nocase ascii wide
                        $string25 = /CyberGhost\.Browser\.dll/ nocase ascii wide
                        $string26 = /CyberGhost\.exe/ nocase ascii wide
                        $string27 = /CyberGhost\.resources\.dll/ nocase ascii wide
                        $string28 = /CyberGhost\.Service\.exe/ nocase ascii wide
                        $string29 = /CyberGhost\.Service\.InstallLog/ nocase ascii wide
                        $string30 = /CyberGhost\.Service\.pdb/ nocase ascii wide
                        $string31 = /CyberGhost\.VPNServices\.dll/ nocase ascii wide
                        $string32 = "CyberGhost6Service" nocase ascii wide
                        $string33 = "CyberGhost7Service" nocase ascii wide
                        $string34 = "CyberGhost8Service" nocase ascii wide
                        $string35 = /CyberGhostTunnel\$CyberGhost\-WireGuard\-1/ nocase ascii wide
                        $string36 = /CyberGhostVPNSetup\.exe/ nocase ascii wide
                        $string37 = /CyberGhost\-WireGuard\-1\.conf/ nocase ascii wide
                        $string38 = /download\.cyberghostvpn\.com/ nocase ascii wide
                        $string39 = /feedback\.cyberghostvpn\.com/ nocase ascii wide
                        $string40 = "ffbkglfijbcbgblgflchnbphjdllaogb" nocase ascii wide
                        $string41 = /payment\.cyberghostvpn\.com/ nocase ascii wide

    condition:
        any of them
}