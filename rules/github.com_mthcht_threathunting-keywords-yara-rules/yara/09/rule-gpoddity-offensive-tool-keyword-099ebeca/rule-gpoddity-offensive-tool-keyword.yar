rule rule_GPOddity_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GPOddity' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GPOddity"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GPOddity_offensive_tool_keyword = /\s\'GPODDITY\$\'\s/ nocase ascii wide
                        $string2_GPOddity_offensive_tool_keyword = /\s\-\-gpo\-id\s.{0,1000}\s\-\-domain\s.{0,1000}\s\-\-command\s/ nocase ascii wide
                        $string3_GPOddity_offensive_tool_keyword = /\s\-\-gpo\-id\s.{0,1000}\s\-\-gpo\-type\s.{0,1000}\s\-\-no\-smb\-server\s/ nocase ascii wide
                        $string4_GPOddity_offensive_tool_keyword = " --rogue-smbserver-ip " nocase ascii wide
                        $string5_GPOddity_offensive_tool_keyword = " --rogue-smbserver-share " nocase ascii wide
                        $string6_GPOddity_offensive_tool_keyword = /\(not\slaunching\sGPOddity\sSMB\sserver\)/ nocase ascii wide
                        $string7_GPOddity_offensive_tool_keyword = /\/GPOddity\.git/ nocase ascii wide
                        $string8_GPOddity_offensive_tool_keyword = "/GPOddity/" nocase ascii wide
                        $string9_GPOddity_offensive_tool_keyword = /\[\!\]\sFailed\sto\sdownload\slegitimate\sGPO\sfrom\sSYSVOL\s\(dc_ip\:/ nocase ascii wide
                        $string10_GPOddity_offensive_tool_keyword = /\[\!\]\sFailed\sto\swrite\smalicious\sscheduled\stask\sto\sdownloaded\sGPO\.\sExiting/ nocase ascii wide
                        $string11_GPOddity_offensive_tool_keyword = /\[.{0,1000}\]\sDownloading\sthe\slegitimate\sGPO\sfrom\sSYSVOL/ nocase ascii wide
                        $string12_GPOddity_offensive_tool_keyword = /\[.{0,1000}\]\sInjecting\smalicious\sscheduled\stask\sinto\sdownloaded\sGPO/ nocase ascii wide
                        $string13_GPOddity_offensive_tool_keyword = /\[.{0,1000}\]\sUpdating\sdownloaded\sGPO\sversion\snumber\sto\sensure\sautomatic\sGPO\sapplication/ nocase ascii wide
                        $string14_GPOddity_offensive_tool_keyword = /\[\+\]\sSuccessfully\sdownloaded\slegitimate\sGPO\sfrom\sSYSVOL\sto\s/ nocase ascii wide
                        $string15_GPOddity_offensive_tool_keyword = /\[\+\]\sSuccessfully\sinjected\smalicious\sscheduled\stask/ nocase ascii wide
                        $string16_GPOddity_offensive_tool_keyword = /\[\+\]\sSuccessfully\sspoofed\sGPC\sgPCFileSysPath\sattribute/ nocase ascii wide
                        $string17_GPOddity_offensive_tool_keyword = /\\GPOddity\\/ nocase ascii wide
                        $string18_GPOddity_offensive_tool_keyword = "=== GENERATING MALICIOUS GROUP POLICY TEMPLATE ===" nocase ascii wide
                        $string19_GPOddity_offensive_tool_keyword = "46993522-7D77-4B59-9B77-F82082DE9D81" nocase ascii wide
                        $string20_GPOddity_offensive_tool_keyword = "Could not write NTLM Hashes to the specified JTR_Dump_Path " nocase ascii wide
                        $string21_GPOddity_offensive_tool_keyword = /Couldn\'t\sclone\sGPO\s\{\}\s\(maybe\sit\sdoes\snot\sexist\?/ nocase ascii wide
                        $string22_GPOddity_offensive_tool_keyword = /from\shelpers\..{0,1000}_smbserver\s.{0,1000}\simport\sSimpleSMBServer/ nocase ascii wide
                        $string23_GPOddity_offensive_tool_keyword = /gpoddity\.py/ nocase ascii wide
                        $string24_GPOddity_offensive_tool_keyword = /gpoddity_smbserver\.py/ nocase ascii wide
                        $string25_GPOddity_offensive_tool_keyword = "GPOddity-master" nocase ascii wide
                        $string26_GPOddity_offensive_tool_keyword = /helpers\.gpoddity_smbserver/ nocase ascii wide
                        $string27_GPOddity_offensive_tool_keyword = /If\sthe\sattack\sis\ssuccessful.{0,1000}\syou\swill\ssee\sauthentication\slogs\sof\smachines\sretrieving\sand\sexecuting\sthe\smalicious\sGPO/ nocase ascii wide
                        $string28_GPOddity_offensive_tool_keyword = /\-\-just\-clean.{0,1000}cleaning\/to_clean\.txt/ nocase ascii wide
                        $string29_GPOddity_offensive_tool_keyword = "LAUNCHING GPODDITY SMB SERVER AND WAITING FOR GPO REQUESTS" nocase ascii wide
                        $string30_GPOddity_offensive_tool_keyword = "net user john H4x00r123" nocase ascii wide
                        $string31_GPOddity_offensive_tool_keyword = /scheduledtask_utils\.py\s/ nocase ascii wide
                        $string32_GPOddity_offensive_tool_keyword = "SPOOFING GROUP POLICY TEMPLATE LOCATION THROUGH gPCFileSysPath" nocase ascii wide
                        $string33_GPOddity_offensive_tool_keyword = "synacktiv/GPOddity" nocase ascii wide
                        $string34_GPOddity_offensive_tool_keyword = "synacktiv_gpoddity" nocase ascii wide
                        $string35_GPOddity_offensive_tool_keyword = "You are trying to target a User Group Policy Object while running the embedded SMB server" nocase ascii wide

    condition:
        any of them
}