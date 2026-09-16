rule o365recon
{
    meta:
        description = "Detection patterns for the tool 'o365recon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365recon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.AzureAD\.Application_Owners\.csv/ nocase ascii wide
                        $string2 = /\.AzureAD\.DeviceList_Owners\.csv/ nocase ascii wide
                        $string3 = /\.O365\.GroupMembership_AdminGroups\.txt/ nocase ascii wide
                        $string4 = /\.O365\.GroupMembership_VPNGroups\.txt/ nocase ascii wide
                        $string5 = /\.O365\.Roles_Admins\.txt/ nocase ascii wide
                        $string6 = /\.O365\.Users_Detailed\.csv/ nocase ascii wide
                        $string7 = /\.O365\.Users_LDAP_details\.txt/ nocase ascii wide
                        $string8 = /\.O365\.Users_ProxyAddresses\.txt/ nocase ascii wide
                        $string9 = /\/o365recon\.git/ nocase ascii wide
                        $string10 = /\\.{0,1000}\.O365\.GroupMembership_AdminGroups\.txt/ nocase ascii wide
                        $string11 = /\\.{0,1000}\.O365\.GroupMembership_VPNGroups\.txt/ nocase ascii wide
                        $string12 = /\\.{0,1000}\.O365\.Roles_Admins\.txt/ nocase ascii wide
                        $string13 = "49df12075c49bb956291cd11b2c53626174b4128309ada438d5d5e49265866f9" nocase ascii wide
                        $string14 = "JOB COMPLETE: GO GET YOUR LOOT!" nocase ascii wide
                        $string15 = "nyxgeek/o365recon" nocase ascii wide
                        $string16 = /o365recon\.ps1/ nocase ascii wide
                        $string17 = "o365recon-master" nocase ascii wide

    condition:
        any of them
}