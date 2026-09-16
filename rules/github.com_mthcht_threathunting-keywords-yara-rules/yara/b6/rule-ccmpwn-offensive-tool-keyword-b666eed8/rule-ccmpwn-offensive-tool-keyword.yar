rule rule_ccmpwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ccmpwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ccmpwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ccmpwn_offensive_tool_keyword = /\sccmpwn\.py/ nocase ascii wide
                        $string2_ccmpwn_offensive_tool_keyword = /\sexec\s\-dll\s.{0,1000}\.dll\s\-config\s.{0,1000}\.config/ nocase ascii wide
                        $string3_ccmpwn_offensive_tool_keyword = /\.py\s.{0,1000}\scoerce\s\-computer\s/ nocase ascii wide
                        $string4_ccmpwn_offensive_tool_keyword = /\/ccmpwn\.git/ nocase ascii wide
                        $string5_ccmpwn_offensive_tool_keyword = /\/ccmpwn\.py/ nocase ascii wide
                        $string6_ccmpwn_offensive_tool_keyword = /\\ccmpwn\.py/ nocase ascii wide
                        $string7_ccmpwn_offensive_tool_keyword = /\\ccmpwn\\/ nocase ascii wide
                        $string8_ccmpwn_offensive_tool_keyword = /\\http_SCNotification\.exe/ nocase ascii wide
                        $string9_ccmpwn_offensive_tool_keyword = /\\smb_SCNotification\.exe/ nocase ascii wide
                        $string10_ccmpwn_offensive_tool_keyword = "5c611fb030683dba08662997836b3b308c0278130bf2eee6ac6af6a4332285fe" nocase ascii wide
                        $string11_ccmpwn_offensive_tool_keyword = "CcmExec might not be installed on target" nocase ascii wide
                        $string12_ccmpwn_offensive_tool_keyword = /CcmExec\sservice\snot\saccessible\son\sremote\ssystem\!\s\:\(/ nocase ascii wide
                        $string13_ccmpwn_offensive_tool_keyword = /Downloading\soriginal\sSCNotification\.exe\.config\svia\sSMB/ nocase ascii wide
                        $string14_ccmpwn_offensive_tool_keyword = /impacket\.dcerpc/ nocase ascii wide
                        $string15_ccmpwn_offensive_tool_keyword = "mandiant/ccmpwn" nocase ascii wide
                        $string16_ccmpwn_offensive_tool_keyword = /SCNotification\.exe\.config\.malicious/ nocase ascii wide
                        $string17_ccmpwn_offensive_tool_keyword = /smbclient\.getFile\(\'C\$\'\,\s\'Windows\/CCM\/SCNotification\.exe\.config/ nocase ascii wide
                        $string18_ccmpwn_offensive_tool_keyword = /Starting\sCcmExec\sservice\.\sWait\saround\s30\sseconds\sfor\sSCNotification\.exe\sto\srun\sconfig\sfile/ nocase ascii wide
                        $string19_ccmpwn_offensive_tool_keyword = /templates\/http_SCNotification\.exe/ nocase ascii wide
                        $string20_ccmpwn_offensive_tool_keyword = /templates\/smb_SCNotification\.exe/ nocase ascii wide
                        $string21_ccmpwn_offensive_tool_keyword = "Uploading malicious DLL via SMB" nocase ascii wide
                        $string22_ccmpwn_offensive_tool_keyword = /Uploading\smalicious\sSCNotification\.exe\.config\svia\sSMB/ nocase ascii wide

    condition:
        any of them
}