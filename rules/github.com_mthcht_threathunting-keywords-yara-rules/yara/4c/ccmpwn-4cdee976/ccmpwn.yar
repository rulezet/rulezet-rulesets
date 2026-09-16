rule ccmpwn
{
    meta:
        description = "Detection patterns for the tool 'ccmpwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ccmpwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sccmpwn\.py/ nocase ascii wide
                        $string2 = /\sexec\s\-dll\s.{0,1000}\.dll\s\-config\s.{0,1000}\.config/ nocase ascii wide
                        $string3 = /\.py\s.{0,1000}\scoerce\s\-computer\s/ nocase ascii wide
                        $string4 = /\/ccmpwn\.git/ nocase ascii wide
                        $string5 = /\/ccmpwn\.py/ nocase ascii wide
                        $string6 = /\\ccmpwn\.py/ nocase ascii wide
                        $string7 = /\\ccmpwn\\/ nocase ascii wide
                        $string8 = /\\http_SCNotification\.exe/ nocase ascii wide
                        $string9 = /\\smb_SCNotification\.exe/ nocase ascii wide
                        $string10 = "5c611fb030683dba08662997836b3b308c0278130bf2eee6ac6af6a4332285fe" nocase ascii wide
                        $string11 = "CcmExec might not be installed on target" nocase ascii wide
                        $string12 = /CcmExec\sservice\snot\saccessible\son\sremote\ssystem\!\s\:\(/ nocase ascii wide
                        $string13 = /Downloading\soriginal\sSCNotification\.exe\.config\svia\sSMB/ nocase ascii wide
                        $string14 = /impacket\.dcerpc/ nocase ascii wide
                        $string15 = "mandiant/ccmpwn" nocase ascii wide
                        $string16 = /SCNotification\.exe\.config\.malicious/ nocase ascii wide
                        $string17 = /smbclient\.getFile\(\'C\$\'\,\s\'Windows\/CCM\/SCNotification\.exe\.config/ nocase ascii wide
                        $string18 = /Starting\sCcmExec\sservice\.\sWait\saround\s30\sseconds\sfor\sSCNotification\.exe\sto\srun\sconfig\sfile/ nocase ascii wide
                        $string19 = /templates\/http_SCNotification\.exe/ nocase ascii wide
                        $string20 = /templates\/smb_SCNotification\.exe/ nocase ascii wide
                        $string21 = "Uploading malicious DLL via SMB" nocase ascii wide
                        $string22 = /Uploading\smalicious\sSCNotification\.exe\.config\svia\sSMB/ nocase ascii wide

    condition:
        any of them
}