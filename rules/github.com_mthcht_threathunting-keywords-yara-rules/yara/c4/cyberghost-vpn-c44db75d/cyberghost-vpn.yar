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
                        $string8 = /\\CyberGhost\.VPN\..{0,100}\.exe/ nocase ascii wide
                        $string9 = /\\CyberGhost\-WireGuard\-1\.conf/ nocase ascii wide
                        $string10 = /\\Dashboard\.exe\.config/ nocase ascii wide
                        $string11 = /\\Program\sFiles\\CyberGhost/ nocase ascii wide
                        $string12 = /\\Windows\\Temp\\.{0,100}\\wireguard\.sys/ nocase ascii wide
                        $string13 = ">CyberGhost 6 Installer<" nocase ascii wide
                        $string14 = ">CyberGhost 7 Installer<" nocase ascii wide
                        $string15 = ">CyberGhost 8 Installer<" nocase ascii wide
                        $string16 = /api\.cyberghostvpn\.com/ nocase ascii wide
                        $string17 = "CyberGhost 6 Service" nocase ascii wide
                        $string18 = "CyberGhost 7 Service" nocase ascii wide
                        $string19 = "CyberGhost 8 Service" nocase ascii wide
                        $string20 = /CyberGhost\sS\.R\.L\./ nocase ascii wide
                        $string21 = "CyberGhost Tunnel Client:" nocase ascii wide
                        $string22 = /cyberghost.{0,100}\\Dashboard\.exe/ nocase ascii wide
                        $string23 = /cyberghost.{0,100}\\Dashboard\.Service\.exe/ nocase ascii wide
                        $string24 = /cyberghost.{0,100}\\wyUpdate\.exe/ nocase ascii wide
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