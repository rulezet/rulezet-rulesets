rule rule_PPLBlade_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PPLBlade' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLBlade"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PPLBlade_offensive_tool_keyword = /\s\-\-dumpmode\snetwork\s\-\-network\sraw\s\-\-ip\s.{0,1000}\s\-\-port\s/ nocase ascii wide
                        $string2_PPLBlade_offensive_tool_keyword = " --dumpmode network --network smb " nocase ascii wide
                        $string3_PPLBlade_offensive_tool_keyword = /\s\-\-dumpname\slsass\.dmp/ nocase ascii wide
                        $string4_PPLBlade_offensive_tool_keyword = " --key PPLBlade" nocase ascii wide
                        $string5_PPLBlade_offensive_tool_keyword = /\s\-\-mode\sdecrypt\s\-\-dumpname\s.{0,1000}\.dmp\s\-\-key\s/ nocase ascii wide
                        $string6_PPLBlade_offensive_tool_keyword = /\s\-\-mode\sdump\s\-\-name\s.{0,1000}\.exe\s\-\-handle\sprocexp\s\-\-obfuscate/ nocase ascii wide
                        $string7_PPLBlade_offensive_tool_keyword = /\s\-\-mode\sdump\s\-\-name\slsass\.exe/ nocase ascii wide
                        $string8_PPLBlade_offensive_tool_keyword = /\/decrypted\.dmp/ nocase ascii wide
                        $string9_PPLBlade_offensive_tool_keyword = /\/PPLBlade\.git/ nocase ascii wide
                        $string10_PPLBlade_offensive_tool_keyword = /\[\+\]\sDeobfuscated\sdump\ssaved\sin\sfile\sdecrypted\.dmp/ nocase ascii wide
                        $string11_PPLBlade_offensive_tool_keyword = /\\decrypted\.dmp/ nocase ascii wide
                        $string12_PPLBlade_offensive_tool_keyword = /\\PPLBlade\-main/ nocase ascii wide
                        $string13_PPLBlade_offensive_tool_keyword = "dothatlsassthing" nocase ascii wide
                        $string14_PPLBlade_offensive_tool_keyword = /PPLBlade\.dmp/ nocase ascii wide
                        $string15_PPLBlade_offensive_tool_keyword = /PPLBlade\.exe/ nocase ascii wide
                        $string16_PPLBlade_offensive_tool_keyword = /PPLBlade\-main\./ nocase ascii wide
                        $string17_PPLBlade_offensive_tool_keyword = "tastypepperoni/PPLBlade" nocase ascii wide

    condition:
        any of them
}