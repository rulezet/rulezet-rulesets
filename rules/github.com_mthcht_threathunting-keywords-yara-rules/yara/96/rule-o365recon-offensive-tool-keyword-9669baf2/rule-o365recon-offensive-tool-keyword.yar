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
                        $string10_o365recon_offensive_tool_keyword = /\\.{0,1000}\.O365\.GroupMembership_AdminGroups\.txt/ nocase ascii wide
                        $string11_o365recon_offensive_tool_keyword = /\\.{0,1000}\.O365\.GroupMembership_VPNGroups\.txt/ nocase ascii wide
                        $string12_o365recon_offensive_tool_keyword = /\\.{0,1000}\.O365\.Roles_Admins\.txt/ nocase ascii wide
                        $string13_o365recon_offensive_tool_keyword = "49df12075c49bb956291cd11b2c53626174b4128309ada438d5d5e49265866f9" nocase ascii wide
                        $string14_o365recon_offensive_tool_keyword = "JOB COMPLETE: GO GET YOUR LOOT!" nocase ascii wide
                        $string15_o365recon_offensive_tool_keyword = "nyxgeek/o365recon" nocase ascii wide
                        $string16_o365recon_offensive_tool_keyword = /o365recon\.ps1/ nocase ascii wide
                        $string17_o365recon_offensive_tool_keyword = "o365recon-master" nocase ascii wide

    condition:
        any of them
}