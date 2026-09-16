rule rule_SharpMapExec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpMapExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpMapExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpMapExec_offensive_tool_keyword = /\s\/m\:assembly\s\/p\:beacon\.exe/ nocase ascii wide
                        $string2_SharpMapExec_offensive_tool_keyword = /\s\/m\:assembly\s\/p\:getMailBox\.exe/ nocase ascii wide
                        $string3_SharpMapExec_offensive_tool_keyword = /\(Get\-Process\slsass\)\.Id/ nocase ascii wide
                        $string4_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\sldap\s.{0,1000}\s\/m\:spraydata/ nocase ascii wide
                        $string5_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\sldap\s.{0,1000}\s\/password\:.{0,1000}\s\/dc\:/ nocase ascii wide
                        $string6_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\sldap\s.{0,1000}\s\/ticket\:.{0,1000}\s\/m\:/ nocase ascii wide
                        $string7_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\sreg32\s.{0,1000}\s\/m\:check_pslockdown/ nocase ascii wide
                        $string8_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\sreg32\s.{0,1000}\s\/m\:check_pslogging/ nocase ascii wide
                        $string9_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\sreg32\s.{0,1000}\s\/m\:disable_pslockdown/ nocase ascii wide
                        $string10_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\sreg32\s.{0,1000}\s\/password\:.{0,1000}\s\/dc\:/ nocase ascii wide
                        $string11_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\sreg32\s.{0,1000}\s\/ticket\:/ nocase ascii wide
                        $string12_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\ssmb\s.{0,1000}\s\/computername\:.{0,1000}\s\/ticket\:/ nocase ascii wide
                        $string13_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\ssmb\s.{0,1000}\s\/m\:shares/ nocase ascii wide
                        $string14_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\ssmb\s.{0,1000}\s\/password\:.{0,1000}\s\/dc\:/ nocase ascii wide
                        $string15_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\ssmb\s.{0,1000}\s\/ticket\:.{0,1000}\s\/computername\:/ nocase ascii wide
                        $string16_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\swinrm\s.{0,1000}\s\/computername\:/ nocase ascii wide
                        $string17_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:assembly\s\/p\:/ nocase ascii wide
                        $string18_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:comsvcs/ nocase ascii wide
                        $string19_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:download\s/ nocase ascii wide
                        $string20_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:exec\s\/a\:/ nocase ascii wide
                        $string21_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:secrets/ nocase ascii wide
                        $string22_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:upload/ nocase ascii wide
                        $string23_SharpMapExec_offensive_tool_keyword = /\.exe\skerberos\swinrm\s.{0,1000}\s\/rc4\:/ nocase ascii wide
                        $string24_SharpMapExec_offensive_tool_keyword = /\.exe\skerbspray\s/ nocase ascii wide
                        $string25_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:check_pslockdown/ nocase ascii wide
                        $string26_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:check_pslogging/ nocase ascii wide
                        $string27_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:disable_pslockdown/ nocase ascii wide
                        $string28_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:disable_pslogging/ nocase ascii wide
                        $string29_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:disable_winrm/ nocase ascii wide
                        $string30_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:enable_winrm/ nocase ascii wide
                        $string31_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\scim\s.{0,1000}\s\/user\:/ nocase ascii wide
                        $string32_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\sldap\s.{0,1000}\s\/m\:spraydata/ nocase ascii wide
                        $string33_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\sldap\s.{0,1000}\s\/password\:/ nocase ascii wide
                        $string34_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\sreg32\s.{0,1000}\s\/m\:check_pslockdown/ nocase ascii wide
                        $string35_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\sreg32\s.{0,1000}\s\/m\:check_pslogging/ nocase ascii wide
                        $string36_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\sreg32\s.{0,1000}\s\/m\:disable_pslockdown/ nocase ascii wide
                        $string37_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\sreg32\s.{0,1000}\s\/ntlm\:/ nocase ascii wide
                        $string38_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\ssmb\s.{0,1000}\s\/m\:shares/ nocase ascii wide
                        $string39_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\ssmb\s.{0,1000}\s\/ntlm\:/ nocase ascii wide
                        $string40_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:assembly\s\/p\:/ nocase ascii wide
                        $string41_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:comsvcs/ nocase ascii wide
                        $string42_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:download/ nocase ascii wide
                        $string43_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:exec\s\/a\:/ nocase ascii wide
                        $string44_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:secrets/ nocase ascii wide
                        $string45_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:upload/ nocase ascii wide
                        $string46_SharpMapExec_offensive_tool_keyword = /\.exe\sntlm\swinrm\s.{0,1000}\s\/password\:/ nocase ascii wide
                        $string47_SharpMapExec_offensive_tool_keyword = /\.exe\stgtdeleg/ nocase ascii wide
                        $string48_SharpMapExec_offensive_tool_keyword = /\/SharpMapExec\.exe/ nocase ascii wide
                        $string49_SharpMapExec_offensive_tool_keyword = /\/SharpMapExec\.git/ nocase ascii wide
                        $string50_SharpMapExec_offensive_tool_keyword = /\\SharpMapExec\.exe/ nocase ascii wide
                        $string51_SharpMapExec_offensive_tool_keyword = /\\SharpMapExec\.sln/ nocase ascii wide
                        $string52_SharpMapExec_offensive_tool_keyword = /\\SharpMapExec\\/ nocase ascii wide
                        $string53_SharpMapExec_offensive_tool_keyword = /\]\sCopying\slsass\sdump/ nocase ascii wide
                        $string54_SharpMapExec_offensive_tool_keyword = ">SharpMapExec<" nocase ascii wide
                        $string55_SharpMapExec_offensive_tool_keyword = "b32521b722e44343d730559adf79326d2f4e3126417d934319ab4088185e0f7b" nocase ascii wide
                        $string56_SharpMapExec_offensive_tool_keyword = /base64\(ticket\.kirbi/ nocase ascii wide
                        $string57_SharpMapExec_offensive_tool_keyword = "BD5220F7-E1FB-41D2-91EC-E4C50C6E9B9F" nocase ascii wide
                        $string58_SharpMapExec_offensive_tool_keyword = /C\:\\\\windows\\\\temp\\\\Coredump\.dmp/ nocase ascii wide
                        $string59_SharpMapExec_offensive_tool_keyword = /C\:\\\\windows\\\\temp\\\\sam/ nocase ascii wide
                        $string60_SharpMapExec_offensive_tool_keyword = /C\:\\windows\\temp\\Coredump\.dmp/ nocase ascii wide
                        $string61_SharpMapExec_offensive_tool_keyword = "cube0x0/SharpMapExec" nocase ascii wide
                        $string62_SharpMapExec_offensive_tool_keyword = "f85996adb68f4d1c09f87c896a686530cc08df05aeaaa885756bf4508470ceaf" nocase ascii wide
                        $string63_SharpMapExec_offensive_tool_keyword = "full; Wait-Process rundll32" nocase ascii wide
                        $string64_SharpMapExec_offensive_tool_keyword = /SharpMapExec\-main\.zip/ nocase ascii wide
                        $string65_SharpMapExec_offensive_tool_keyword = "Using a domain DPAPI backup key to triage masterkeys for decryption key mappings" nocase ascii wide

    condition:
        any of them
}