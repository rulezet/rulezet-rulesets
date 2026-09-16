rule rule_Invoke_Maldaptive_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Maldaptive' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Maldaptive"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Invoke_Maldaptive_greyware_tool_keyword = /\/Invoke\-Maldaptive\.git/ nocase ascii wide
                        $string2_Invoke_Maldaptive_greyware_tool_keyword = /\\Invoke\-Maldaptive\-main/ nocase ascii wide
                        $string3_Invoke_Maldaptive_greyware_tool_keyword = /\\Obfuscated_Command\.txt/ nocase ascii wide
                        $string4_Invoke_Maldaptive_greyware_tool_keyword = "275de3390b20723991268204fb3f70b0ec76dba29f809ac0152588cecc22e87f" nocase ascii wide
                        $string5_Invoke_Maldaptive_greyware_tool_keyword = "50c178847f0454a84f85bc765699c1180ea1b49f91e7d70b5b9113845d008387" nocase ascii wide
                        $string6_Invoke_Maldaptive_greyware_tool_keyword = "7215255a842142ffa7f7e1624942684279e9a2f14fa7947451a3194d0b608f52" nocase ascii wide
                        $string7_Invoke_Maldaptive_greyware_tool_keyword = "db015ab1-abcd-1234-5678-133337c0ffee" nocase ascii wide
                        $string8_Invoke_Maldaptive_greyware_tool_keyword = "Disable-LdapClientWinEvent -ProcessName " nocase ascii wide
                        $string9_Invoke_Maldaptive_greyware_tool_keyword = "e8f71ea9428bb466651b9cd3a2ed3a726d1a07712bd611330def1ebfcbc68b47" nocase ascii wide
                        $string10_Invoke_Maldaptive_greyware_tool_keyword = /https\:\/\/github\.com\/mandiant\/SilkETW\/releases\/download\/v0\.8\/SilkETW_SilkService_v8\.zip/ nocase ascii wide
                        $string11_Invoke_Maldaptive_greyware_tool_keyword = "Invoke-LdapBranchVisitor" nocase ascii wide
                        $string12_Invoke_Maldaptive_greyware_tool_keyword = /Invoke\-LdapQuery\s\-.{0,1000}ConvertFrom\-LdapSearchResult/ nocase ascii wide
                        $string13_Invoke_Maldaptive_greyware_tool_keyword = "Invoke-Maldaptive" nocase ascii wide
                        $string14_Invoke_Maldaptive_greyware_tool_keyword = "MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection" nocase ascii wide
                        $string15_Invoke_Maldaptive_greyware_tool_keyword = /Maldaptive\.pd1/ nocase ascii wide
                        $string16_Invoke_Maldaptive_greyware_tool_keyword = /Maldaptive\.psm1/ nocase ascii wide
                        $string17_Invoke_Maldaptive_greyware_tool_keyword = "MaLDAPtive/Invoke-Maldaptive" nocase ascii wide
                        $string18_Invoke_Maldaptive_greyware_tool_keyword = /New\-ObfuscationContainer\s\-SearchFilter\s\$SearchFilter\s\-SearchRoot\:\$SearchRoot\s\-AttributeList/ nocase ascii wide
                        $string19_Invoke_Maldaptive_greyware_tool_keyword = "serviceName = 'SilkService" nocase ascii wide

    condition:
        any of them
}