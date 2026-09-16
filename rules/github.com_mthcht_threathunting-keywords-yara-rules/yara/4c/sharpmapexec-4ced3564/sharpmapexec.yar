rule SharpMapExec
{
    meta:
        description = "Detection patterns for the tool 'SharpMapExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpMapExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\/m\:assembly\s\/p\:beacon\.exe/ nocase ascii wide
                        $string2 = /\s\/m\:assembly\s\/p\:getMailBox\.exe/ nocase ascii wide
                        $string3 = /\(Get\-Process\slsass\)\.Id/ nocase ascii wide
                        $string4 = /\.exe\skerberos\sldap\s.{0,1000}\s\/m\:spraydata/ nocase ascii wide
                        $string5 = /\.exe\skerberos\sldap\s.{0,1000}\s\/password\:.{0,1000}\s\/dc\:/ nocase ascii wide
                        $string6 = /\.exe\skerberos\sldap\s.{0,1000}\s\/ticket\:.{0,1000}\s\/m\:/ nocase ascii wide
                        $string7 = /\.exe\skerberos\sreg32\s.{0,1000}\s\/m\:check_pslockdown/ nocase ascii wide
                        $string8 = /\.exe\skerberos\sreg32\s.{0,1000}\s\/m\:check_pslogging/ nocase ascii wide
                        $string9 = /\.exe\skerberos\sreg32\s.{0,1000}\s\/m\:disable_pslockdown/ nocase ascii wide
                        $string10 = /\.exe\skerberos\sreg32\s.{0,1000}\s\/password\:.{0,1000}\s\/dc\:/ nocase ascii wide
                        $string11 = /\.exe\skerberos\sreg32\s.{0,1000}\s\/ticket\:/ nocase ascii wide
                        $string12 = /\.exe\skerberos\ssmb\s.{0,1000}\s\/computername\:.{0,1000}\s\/ticket\:/ nocase ascii wide
                        $string13 = /\.exe\skerberos\ssmb\s.{0,1000}\s\/m\:shares/ nocase ascii wide
                        $string14 = /\.exe\skerberos\ssmb\s.{0,1000}\s\/password\:.{0,1000}\s\/dc\:/ nocase ascii wide
                        $string15 = /\.exe\skerberos\ssmb\s.{0,1000}\s\/ticket\:.{0,1000}\s\/computername\:/ nocase ascii wide
                        $string16 = /\.exe\skerberos\swinrm\s.{0,1000}\s\/computername\:/ nocase ascii wide
                        $string17 = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:assembly\s\/p\:/ nocase ascii wide
                        $string18 = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:comsvcs/ nocase ascii wide
                        $string19 = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:download\s/ nocase ascii wide
                        $string20 = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:exec\s\/a\:/ nocase ascii wide
                        $string21 = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:secrets/ nocase ascii wide
                        $string22 = /\.exe\skerberos\swinrm\s.{0,1000}\s\/m\:upload/ nocase ascii wide
                        $string23 = /\.exe\skerberos\swinrm\s.{0,1000}\s\/rc4\:/ nocase ascii wide
                        $string24 = /\.exe\skerbspray\s/ nocase ascii wide
                        $string25 = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:check_pslockdown/ nocase ascii wide
                        $string26 = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:check_pslogging/ nocase ascii wide
                        $string27 = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:disable_pslockdown/ nocase ascii wide
                        $string28 = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:disable_pslogging/ nocase ascii wide
                        $string29 = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:disable_winrm/ nocase ascii wide
                        $string30 = /\.exe\sntlm\scim\s.{0,1000}\s\/m\:enable_winrm/ nocase ascii wide
                        $string31 = /\.exe\sntlm\scim\s.{0,1000}\s\/user\:/ nocase ascii wide
                        $string32 = /\.exe\sntlm\sldap\s.{0,1000}\s\/m\:spraydata/ nocase ascii wide
                        $string33 = /\.exe\sntlm\sldap\s.{0,1000}\s\/password\:/ nocase ascii wide
                        $string34 = /\.exe\sntlm\sreg32\s.{0,1000}\s\/m\:check_pslockdown/ nocase ascii wide
                        $string35 = /\.exe\sntlm\sreg32\s.{0,1000}\s\/m\:check_pslogging/ nocase ascii wide
                        $string36 = /\.exe\sntlm\sreg32\s.{0,1000}\s\/m\:disable_pslockdown/ nocase ascii wide
                        $string37 = /\.exe\sntlm\sreg32\s.{0,1000}\s\/ntlm\:/ nocase ascii wide
                        $string38 = /\.exe\sntlm\ssmb\s.{0,1000}\s\/m\:shares/ nocase ascii wide
                        $string39 = /\.exe\sntlm\ssmb\s.{0,1000}\s\/ntlm\:/ nocase ascii wide
                        $string40 = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:assembly\s\/p\:/ nocase ascii wide
                        $string41 = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:comsvcs/ nocase ascii wide
                        $string42 = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:download/ nocase ascii wide
                        $string43 = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:exec\s\/a\:/ nocase ascii wide
                        $string44 = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:secrets/ nocase ascii wide
                        $string45 = /\.exe\sntlm\swinrm\s.{0,1000}\s\/m\:upload/ nocase ascii wide
                        $string46 = /\.exe\sntlm\swinrm\s.{0,1000}\s\/password\:/ nocase ascii wide
                        $string47 = /\.exe\stgtdeleg/ nocase ascii wide
                        $string48 = /\/SharpMapExec\.exe/ nocase ascii wide
                        $string49 = /\/SharpMapExec\.git/ nocase ascii wide
                        $string50 = /\\SharpMapExec\.exe/ nocase ascii wide
                        $string51 = /\\SharpMapExec\.sln/ nocase ascii wide
                        $string52 = /\\SharpMapExec\\/ nocase ascii wide
                        $string53 = /\]\sCopying\slsass\sdump/ nocase ascii wide
                        $string54 = ">SharpMapExec<" nocase ascii wide
                        $string55 = "b32521b722e44343d730559adf79326d2f4e3126417d934319ab4088185e0f7b" nocase ascii wide
                        $string56 = /base64\(ticket\.kirbi/ nocase ascii wide
                        $string57 = "BD5220F7-E1FB-41D2-91EC-E4C50C6E9B9F" nocase ascii wide
                        $string58 = /C\:\\\\windows\\\\temp\\\\Coredump\.dmp/ nocase ascii wide
                        $string59 = /C\:\\\\windows\\\\temp\\\\sam/ nocase ascii wide
                        $string60 = /C\:\\windows\\temp\\Coredump\.dmp/ nocase ascii wide
                        $string61 = "cube0x0/SharpMapExec" nocase ascii wide
                        $string62 = "f85996adb68f4d1c09f87c896a686530cc08df05aeaaa885756bf4508470ceaf" nocase ascii wide
                        $string63 = "full; Wait-Process rundll32" nocase ascii wide
                        $string64 = /SharpMapExec\-main\.zip/ nocase ascii wide
                        $string65 = "Using a domain DPAPI backup key to triage masterkeys for decryption key mappings" nocase ascii wide

    condition:
        any of them
}