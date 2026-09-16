rule rule_o365recon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'o365recon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365recon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_o365recon_offensive_tool_keyword = /\.AzureAD\.Application_Owners\.csv/ nocase ascii wide
                        $string2_o365recon_offensive_tool_keyword = /\.AzureAD\.DeviceList_Owners\.csv/ nocase ascii wide
                        $string3_o365recon_offensive_tool_keyword = /\.O365\.GroupMembership_AdminGroups\.txt/ nocase ascii wide
                        $string4_o365recon_offensive_tool_keyword = /\.O365\.GroupMembership_VPNGroups\.txt/ nocase ascii wide
                        $string5_o365recon_offensive_tool_keyword = /\.O365\.Roles_Admins\.txt/ nocase ascii wide
                        $string6_o365recon_offensive_tool_keyword = /\.O365\.Users_Detailed\.csv/ nocase ascii wide
                        $string7_o365recon_offensive_tool_keyword = /\.O365\.Users_LDAP_details\.txt/ nocase ascii wide
                        $string8_o365recon_offensive_tool_keyword = /\.O365\.Users_ProxyAddresses\.txt/ nocase ascii wide
                        $string9_o365recon_offensive_tool_keyword = /\/o365recon\.git/ nocase ascii wide
                        $string10_o365recon_offensive_tool_keyword = /\\.{0,100}\.O365\.GroupMembership_AdminGroups\.txt/ nocase ascii wide
                        $string11_o365recon_offensive_tool_keyword = /\\.{0,100}\.O365\.GroupMembership_VPNGroups\.txt/ nocase ascii wide
                        $string12_o365recon_offensive_tool_keyword = /\\.{0,100}\.O365\.Roles_Admins\.txt/ nocase ascii wide
                        $string13_o365recon_offensive_tool_keyword = "49df12075c49bb956291cd11b2c53626174b4128309ada438d5d5e49265866f9" nocase ascii wide
                        $string14_o365recon_offensive_tool_keyword = "JOB COMPLETE: GO GET YOUR LOOT!" nocase ascii wide
                        $string15_o365recon_offensive_tool_keyword = "nyxgeek/o365recon" nocase ascii wide
                        $string16_o365recon_offensive_tool_keyword = /o365recon\.ps1/ nocase ascii wide
                        $string17_o365recon_offensive_tool_keyword = "o365recon-master" nocase ascii wide
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