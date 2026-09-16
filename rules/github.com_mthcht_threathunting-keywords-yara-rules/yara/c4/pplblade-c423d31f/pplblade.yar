rule PPLBlade
{
    meta:
        description = "Detection patterns for the tool 'PPLBlade' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLBlade"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-dumpmode\snetwork\s\-\-network\sraw\s\-\-ip\s.{0,1000}\s\-\-port\s/ nocase ascii wide
                        $string2 = " --dumpmode network --network smb " nocase ascii wide
                        $string3 = /\s\-\-dumpname\slsass\.dmp/ nocase ascii wide
                        $string4 = " --key PPLBlade" nocase ascii wide
                        $string5 = /\s\-\-mode\sdecrypt\s\-\-dumpname\s.{0,1000}\.dmp\s\-\-key\s/ nocase ascii wide
                        $string6 = /\s\-\-mode\sdump\s\-\-name\s.{0,1000}\.exe\s\-\-handle\sprocexp\s\-\-obfuscate/ nocase ascii wide
                        $string7 = /\s\-\-mode\sdump\s\-\-name\slsass\.exe/ nocase ascii wide
                        $string8 = /\/decrypted\.dmp/ nocase ascii wide
                        $string9 = /\/PPLBlade\.git/ nocase ascii wide
                        $string10 = /\[\+\]\sDeobfuscated\sdump\ssaved\sin\sfile\sdecrypted\.dmp/ nocase ascii wide
                        $string11 = /\\decrypted\.dmp/ nocase ascii wide
                        $string12 = /\\PPLBlade\-main/ nocase ascii wide
                        $string13 = "dothatlsassthing" nocase ascii wide
                        $string14 = /PPLBlade\.dmp/ nocase ascii wide
                        $string15 = /PPLBlade\.exe/ nocase ascii wide
                        $string16 = /PPLBlade\-main\./ nocase ascii wide
                        $string17 = "tastypepperoni/PPLBlade" nocase ascii wide

    condition:
        any of them
}