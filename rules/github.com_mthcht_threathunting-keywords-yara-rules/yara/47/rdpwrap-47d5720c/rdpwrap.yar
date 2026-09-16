rule rdpwrap
{
    meta:
        description = "Detection patterns for the tool 'rdpwrap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdpwrap"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sRDPWInst\.exe/ nocase ascii wide
                        $string2 = /\srdpwrap\.dll/ nocase ascii wide
                        $string3 = "\"%~dp0RDPWInst\" -i -o" nocase ascii wide
                        $string4 = /\%\~dp0RDPWInst\.exe/ nocase ascii wide
                        $string5 = /\/RDPWInst\.exe/ nocase ascii wide
                        $string6 = /\/RDPWInst\-v.{0,1000}\.msi/ nocase ascii wide
                        $string7 = /\/rdpwrap\.dll/ nocase ascii wide
                        $string8 = /\/rdpwrap\.git/ nocase ascii wide
                        $string9 = /\/RDPWrap\-v.{0,1000}\.zip/ nocase ascii wide
                        $string10 = /\/res\/rdpwrap\.ini/ nocase ascii wide
                        $string11 = /\\bin\\RDPConf\.exe/ nocase ascii wide
                        $string12 = /\\RDP\sWrapper\\/ nocase ascii wide
                        $string13 = /\\RDPCheck\.exe/ nocase ascii wide
                        $string14 = /\\RDPWInst\.exe/ nocase ascii wide
                        $string15 = /\\RDPWInst\-v.{0,1000}\.msi/ nocase ascii wide
                        $string16 = /\\RDPWrap\.cpp/ nocase ascii wide
                        $string17 = /\\rdpwrap\.dll/ nocase ascii wide
                        $string18 = /\\rdpwrap\.ini/ nocase ascii wide
                        $string19 = /\\RDPWrap\.sln/ nocase ascii wide
                        $string20 = /\\rdpwrap\.txt/ nocase ascii wide
                        $string21 = /\\rdpwrap\-master/ nocase ascii wide
                        $string22 = /\\RDPWrapSetup/ nocase ascii wide
                        $string23 = /\\RDPWrap\-v.{0,1000}\.zip/ nocase ascii wide
                        $string24 = "1232372059db3ecf28cc2609a36b7f20cef2dfe0618770e3ebaa9488bc7fc2de" nocase ascii wide
                        $string25 = "29E4E73B-EBA6-495B-A76C-FBB462196C64" nocase ascii wide
                        $string26 = "35a9481ddbed5177431a9ea4bd09468fe987797d7b1231d64942d17eb54ec269" nocase ascii wide
                        $string27 = "3699b102bf5ad1120ef560ae3036f27c74f6161b62b31fda8087bd7ae1496ee1" nocase ascii wide
                        $string28 = "9899ffecf141ab4535ec702facbf2b4233903b428b862f3a87e635d09c6244de" nocase ascii wide
                        $string29 = "aaf7e238a5c0bb2a7956e2fdca9b534f227f7b737641962fb0ed965390ace4c6" nocase ascii wide
                        $string30 = "f9a82873a1e55bb1b5b8b8781b06799ff665464cff8ce77e07474c089123b643" nocase ascii wide
                        $string31 = "fed08bd733b8e60b5805007bd01a7bf0d0b1993059bbe319d1179facc6b73361" nocase ascii wide
                        $string32 = "Initializing RDP Wrapper" nocase ascii wide
                        $string33 = /\'RDP\sWrapper\sLibrary\sInstaller\sv1\.0\'/ nocase ascii wide
                        $string34 = /RDP\sWrapper\\RDPConf/ nocase ascii wide
                        $string35 = "RDPWInst -w" nocase ascii wide
                        $string36 = /rdpwrap\\.{0,1000}\\RDPWInst\./ nocase ascii wide
                        $string37 = "stascorp/rdpwrap" nocase ascii wide

    condition:
        any of them
}