rule rule_Ouned_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ouned' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ouned"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Ouned_offensive_tool_keyword = /\saddcomputer_LDAP_spn\.py/ nocase ascii wide
                        $string2_Ouned_offensive_tool_keyword = /\saddcomputer_with_spns\.py\s/ nocase ascii wide
                        $string3_Ouned_offensive_tool_keyword = /\s\-\-config\s.{0,1000}\s\-\-just\-clean\s\-\-cleaning\-file\s/ nocase ascii wide
                        $string4_Ouned_offensive_tool_keyword = /\souned_smbserver\.py/ nocase ascii wide
                        $string5_Ouned_offensive_tool_keyword = /\.py\s.{0,1000}\s\-\-coerce\-to\s/ nocase ascii wide
                        $string6_Ouned_offensive_tool_keyword = /\.py\s.{0,1000}\s\-\-just\-coerce\s/ nocase ascii wide
                        $string7_Ouned_offensive_tool_keyword = /\/addcomputer_LDAP_spn\.py/ nocase ascii wide
                        $string8_Ouned_offensive_tool_keyword = /\/addcomputer_with_spns\.py/ nocase ascii wide
                        $string9_Ouned_offensive_tool_keyword = /\/OUned\.git/ nocase ascii wide
                        $string10_Ouned_offensive_tool_keyword = /\/ouned_smbserver\.py/ nocase ascii wide
                        $string11_Ouned_offensive_tool_keyword = /\[\+\]\sSuccessfully\sdownloaded\sGPO\sfrom\sfakedc\sto\s/ nocase ascii wide
                        $string12_Ouned_offensive_tool_keyword = /\[\+\]\sSuccessfully\sinjected\smalicious\sscheduled\stask/ nocase ascii wide
                        $string13_Ouned_offensive_tool_keyword = /\[\+\]\sSuccessfully\sspoofed\sgPLink\sfor\sOU\s/ nocase ascii wide
                        $string14_Ouned_offensive_tool_keyword = /\[\+\]\sSuccessfully\supdated\sextension\snames\sof\sfakedc\sGPO/ nocase ascii wide
                        $string15_Ouned_offensive_tool_keyword = /\[\+\]\sSuccessfully\suploaded\sGPO\sto\sSMB\sserver\s/ nocase ascii wide
                        $string16_Ouned_offensive_tool_keyword = /\\\\\\\\\{attacker_ip\}\\\\/ nocase ascii wide
                        $string17_Ouned_offensive_tool_keyword = /\\\\\\\\\{coerce_to\}\\\\/ nocase ascii wide
                        $string18_Ouned_offensive_tool_keyword = /\\addcomputer_LDAP_spn\.py/ nocase ascii wide
                        $string19_Ouned_offensive_tool_keyword = /\\addcomputer_with_spns\.py/ nocase ascii wide
                        $string20_Ouned_offensive_tool_keyword = /\\ouned_smbserver\.py/ nocase ascii wide
                        $string21_Ouned_offensive_tool_keyword = /\]\sCloning\sGPO\s.{0,1000}\sfrom\sfakedc\s/ nocase ascii wide
                        $string22_Ouned_offensive_tool_keyword = /\]\sInjecting\smalicious\sscheduled\stask\sinto\sdownloaded\sGPO/ nocase ascii wide
                        $string23_Ouned_offensive_tool_keyword = /\]\sModifying\s.{0,1000}\sattribute\sof\sGPO\son\sfakedc\sto\s/ nocase ascii wide
                        $string24_Ouned_offensive_tool_keyword = /\]\sModifying\sgPCFileSysPath\sattribute\sof\sGPO\son\sfakedc\sto\s/ nocase ascii wide
                        $string25_Ouned_offensive_tool_keyword = /\]\sSpoofing\sgPLink\sto\s/ nocase ascii wide
                        $string26_Ouned_offensive_tool_keyword = "=== LAUNCHING SMB SERVER AND WAITING FOR GPT REQUESTS ===" nocase ascii wide
                        $string27_Ouned_offensive_tool_keyword = "=== SPOOFING THE GPLINK ATTRIBUTE OF THE TARGET OU ===" nocase ascii wide
                        $string28_Ouned_offensive_tool_keyword = /\=\=\=\sWAITING\s\(GPT\sREQUESTS\sWILL\sBE\sFORWARDED\sTO\sSMB\sSERVER\)\s\=\=\=/ nocase ascii wide
                        $string29_Ouned_offensive_tool_keyword = /\=\=\=\sWAITING\s\(SMB\sNTLM\sAUTHENTICATION\sCOERCED\sTO\s/ nocase ascii wide
                        $string30_Ouned_offensive_tool_keyword = "92bc6c12e5ead3c0c0069b53bcca9c2f21b9f2e10f1e4a05ef1efcd25bcc70e9" nocase ascii wide
                        $string31_Ouned_offensive_tool_keyword = "99b685e2a57dbbdb0b53689aec5eef525a632c9ea00a5a16adb939387bf5a4da" nocase ascii wide
                        $string32_Ouned_offensive_tool_keyword = "Could not write NTLM Hashes to the specified JTR_Dump_Path" nocase ascii wide
                        $string33_Ouned_offensive_tool_keyword = /https\:\/\/www\.synacktiv\.com\/publications\/ounedpy\-exploiting\-hidden\-organizational\-units\-acl\-attack\-vectors\-in\-active\-directory/ nocase ascii wide
                        $string34_Ouned_offensive_tool_keyword = "net user john H4x00r123" nocase ascii wide
                        $string35_Ouned_offensive_tool_keyword = /Successfully\scloned\sGPO\s.{0,1000}\sfrom\sSYSVOL/ nocase ascii wide
                        $string36_Ouned_offensive_tool_keyword = "synacktiv/OUned" nocase ascii wide

    condition:
        any of them
}