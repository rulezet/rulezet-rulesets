rule rule_rdpwrap_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rdpwrap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdpwrap"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_rdpwrap_greyware_tool_keyword = /\sRDPWInst\.exe/ nocase ascii wide
                        $string2_rdpwrap_greyware_tool_keyword = /\srdpwrap\.dll/ nocase ascii wide
                        $string3_rdpwrap_greyware_tool_keyword = "\"%~dp0RDPWInst\" -i -o" nocase ascii wide
                        $string4_rdpwrap_greyware_tool_keyword = /\%\~dp0RDPWInst\.exe/ nocase ascii wide
                        $string5_rdpwrap_greyware_tool_keyword = /\/RDPWInst\.exe/ nocase ascii wide
                        $string6_rdpwrap_greyware_tool_keyword = /\/RDPWInst\-v.{0,100}\.msi/ nocase ascii wide
                        $string7_rdpwrap_greyware_tool_keyword = /\/rdpwrap\.dll/ nocase ascii wide
                        $string8_rdpwrap_greyware_tool_keyword = /\/rdpwrap\.git/ nocase ascii wide
                        $string9_rdpwrap_greyware_tool_keyword = /\/RDPWrap\-v.{0,100}\.zip/ nocase ascii wide
                        $string10_rdpwrap_greyware_tool_keyword = /\/res\/rdpwrap\.ini/ nocase ascii wide
                        $string11_rdpwrap_greyware_tool_keyword = /\\bin\\RDPConf\.exe/ nocase ascii wide
                        $string12_rdpwrap_greyware_tool_keyword = /\\RDP\sWrapper\\/ nocase ascii wide
                        $string13_rdpwrap_greyware_tool_keyword = /\\RDPCheck\.exe/ nocase ascii wide
                        $string14_rdpwrap_greyware_tool_keyword = /\\RDPWInst\.exe/ nocase ascii wide
                        $string15_rdpwrap_greyware_tool_keyword = /\\RDPWInst\-v.{0,100}\.msi/ nocase ascii wide
                        $string16_rdpwrap_greyware_tool_keyword = /\\RDPWrap\.cpp/ nocase ascii wide
                        $string17_rdpwrap_greyware_tool_keyword = /\\rdpwrap\.dll/ nocase ascii wide
                        $string18_rdpwrap_greyware_tool_keyword = /\\rdpwrap\.ini/ nocase ascii wide
                        $string19_rdpwrap_greyware_tool_keyword = /\\RDPWrap\.sln/ nocase ascii wide
                        $string20_rdpwrap_greyware_tool_keyword = /\\rdpwrap\.txt/ nocase ascii wide
                        $string21_rdpwrap_greyware_tool_keyword = /\\rdpwrap\-master/ nocase ascii wide
                        $string22_rdpwrap_greyware_tool_keyword = /\\RDPWrapSetup/ nocase ascii wide
                        $string23_rdpwrap_greyware_tool_keyword = /\\RDPWrap\-v.{0,100}\.zip/ nocase ascii wide
                        $string24_rdpwrap_greyware_tool_keyword = "1232372059db3ecf28cc2609a36b7f20cef2dfe0618770e3ebaa9488bc7fc2de" nocase ascii wide
                        $string25_rdpwrap_greyware_tool_keyword = "29E4E73B-EBA6-495B-A76C-FBB462196C64" nocase ascii wide
                        $string26_rdpwrap_greyware_tool_keyword = "35a9481ddbed5177431a9ea4bd09468fe987797d7b1231d64942d17eb54ec269" nocase ascii wide
                        $string27_rdpwrap_greyware_tool_keyword = "3699b102bf5ad1120ef560ae3036f27c74f6161b62b31fda8087bd7ae1496ee1" nocase ascii wide
                        $string28_rdpwrap_greyware_tool_keyword = "9899ffecf141ab4535ec702facbf2b4233903b428b862f3a87e635d09c6244de" nocase ascii wide
                        $string29_rdpwrap_greyware_tool_keyword = "aaf7e238a5c0bb2a7956e2fdca9b534f227f7b737641962fb0ed965390ace4c6" nocase ascii wide
                        $string30_rdpwrap_greyware_tool_keyword = "f9a82873a1e55bb1b5b8b8781b06799ff665464cff8ce77e07474c089123b643" nocase ascii wide
                        $string31_rdpwrap_greyware_tool_keyword = "fed08bd733b8e60b5805007bd01a7bf0d0b1993059bbe319d1179facc6b73361" nocase ascii wide
                        $string32_rdpwrap_greyware_tool_keyword = "Initializing RDP Wrapper" nocase ascii wide
                        $string33_rdpwrap_greyware_tool_keyword = /\'RDP\sWrapper\sLibrary\sInstaller\sv1\.0\'/ nocase ascii wide
                        $string34_rdpwrap_greyware_tool_keyword = /RDP\sWrapper\\RDPConf/ nocase ascii wide
                        $string35_rdpwrap_greyware_tool_keyword = "RDPWInst -w" nocase ascii wide
                        $string36_rdpwrap_greyware_tool_keyword = /rdpwrap\\.{0,100}\\RDPWInst\./ nocase ascii wide
                        $string37_rdpwrap_greyware_tool_keyword = "stascorp/rdpwrap" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}