rule Ouned
{
    meta:
        description = "Detection patterns for the tool 'Ouned' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ouned"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\saddcomputer_LDAP_spn\.py/ nocase ascii wide
                        $string2 = /\saddcomputer_with_spns\.py\s/ nocase ascii wide
                        $string3 = /\s\-\-config\s.{0,1000}\s\-\-just\-clean\s\-\-cleaning\-file\s/ nocase ascii wide
                        $string4 = /\souned_smbserver\.py/ nocase ascii wide
                        $string5 = /\.py\s.{0,1000}\s\-\-coerce\-to\s/ nocase ascii wide
                        $string6 = /\.py\s.{0,1000}\s\-\-just\-coerce\s/ nocase ascii wide
                        $string7 = /\/addcomputer_LDAP_spn\.py/ nocase ascii wide
                        $string8 = /\/addcomputer_with_spns\.py/ nocase ascii wide
                        $string9 = /\/OUned\.git/ nocase ascii wide
                        $string10 = /\/ouned_smbserver\.py/ nocase ascii wide
                        $string11 = /\[\+\]\sSuccessfully\sdownloaded\sGPO\sfrom\sfakedc\sto\s/ nocase ascii wide
                        $string12 = /\[\+\]\sSuccessfully\sinjected\smalicious\sscheduled\stask/ nocase ascii wide
                        $string13 = /\[\+\]\sSuccessfully\sspoofed\sgPLink\sfor\sOU\s/ nocase ascii wide
                        $string14 = /\[\+\]\sSuccessfully\supdated\sextension\snames\sof\sfakedc\sGPO/ nocase ascii wide
                        $string15 = /\[\+\]\sSuccessfully\suploaded\sGPO\sto\sSMB\sserver\s/ nocase ascii wide
                        $string16 = /\\\\\\\\\{attacker_ip\}\\\\/ nocase ascii wide
                        $string17 = /\\\\\\\\\{coerce_to\}\\\\/ nocase ascii wide
                        $string18 = /\\addcomputer_LDAP_spn\.py/ nocase ascii wide
                        $string19 = /\\addcomputer_with_spns\.py/ nocase ascii wide
                        $string20 = /\\ouned_smbserver\.py/ nocase ascii wide
                        $string21 = /\]\sCloning\sGPO\s.{0,1000}\sfrom\sfakedc\s/ nocase ascii wide
                        $string22 = /\]\sInjecting\smalicious\sscheduled\stask\sinto\sdownloaded\sGPO/ nocase ascii wide
                        $string23 = /\]\sModifying\s.{0,1000}\sattribute\sof\sGPO\son\sfakedc\sto\s/ nocase ascii wide
                        $string24 = /\]\sModifying\sgPCFileSysPath\sattribute\sof\sGPO\son\sfakedc\sto\s/ nocase ascii wide
                        $string25 = /\]\sSpoofing\sgPLink\sto\s/ nocase ascii wide
                        $string26 = "=== LAUNCHING SMB SERVER AND WAITING FOR GPT REQUESTS ===" nocase ascii wide
                        $string27 = "=== SPOOFING THE GPLINK ATTRIBUTE OF THE TARGET OU ===" nocase ascii wide
                        $string28 = /\=\=\=\sWAITING\s\(GPT\sREQUESTS\sWILL\sBE\sFORWARDED\sTO\sSMB\sSERVER\)\s\=\=\=/ nocase ascii wide
                        $string29 = /\=\=\=\sWAITING\s\(SMB\sNTLM\sAUTHENTICATION\sCOERCED\sTO\s/ nocase ascii wide
                        $string30 = "92bc6c12e5ead3c0c0069b53bcca9c2f21b9f2e10f1e4a05ef1efcd25bcc70e9" nocase ascii wide
                        $string31 = "99b685e2a57dbbdb0b53689aec5eef525a632c9ea00a5a16adb939387bf5a4da" nocase ascii wide
                        $string32 = "Could not write NTLM Hashes to the specified JTR_Dump_Path" nocase ascii wide
                        $string33 = /https\:\/\/www\.synacktiv\.com\/publications\/ounedpy\-exploiting\-hidden\-organizational\-units\-acl\-attack\-vectors\-in\-active\-directory/ nocase ascii wide
                        $string34 = "net user john H4x00r123" nocase ascii wide
                        $string35 = /Successfully\scloned\sGPO\s.{0,1000}\sfrom\sSYSVOL/ nocase ascii wide
                        $string36 = "synacktiv/OUned" nocase ascii wide

    condition:
        any of them
}