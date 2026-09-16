rule rule_Omnispray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Omnispray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Omnispray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Omnispray_offensive_tool_keyword = /\sadfs\-spray\.py/ nocase ascii wide
                        $string2_Omnispray_offensive_tool_keyword = /\sEASSniper\.ps1/ nocase ascii wide
                        $string3_Omnispray_offensive_tool_keyword = " --module o365_spray_activesync" nocase ascii wide
                        $string4_Omnispray_offensive_tool_keyword = /\so365_enum_activesync\.py/ nocase ascii wide
                        $string5_Omnispray_offensive_tool_keyword = /\so365_enum_office\.py/ nocase ascii wide
                        $string6_Omnispray_offensive_tool_keyword = /\so365_enum_onedrive\.py/ nocase ascii wide
                        $string7_Omnispray_offensive_tool_keyword = /\so365_spray_activesync\.py/ nocase ascii wide
                        $string8_Omnispray_offensive_tool_keyword = /\so365_spray_adfs\.py/ nocase ascii wide
                        $string9_Omnispray_offensive_tool_keyword = /\so365_spray_msol\.py/ nocase ascii wide
                        $string10_Omnispray_offensive_tool_keyword = /\somnispray\.py/ nocase ascii wide
                        $string11_Omnispray_offensive_tool_keyword = /\sowa_enum_activesync\.py/ nocase ascii wide
                        $string12_Omnispray_offensive_tool_keyword = /\sowa_spray_activesync\.py/ nocase ascii wide
                        $string13_Omnispray_offensive_tool_keyword = /\spaloalto_enum_globalprotectportal\.py/ nocase ascii wide
                        $string14_Omnispray_offensive_tool_keyword = /\spaloalto_spray_globalprotectportal\.py/ nocase ascii wide
                        $string15_Omnispray_offensive_tool_keyword = /\s\-\-type\senum\s\-uf\s.{0,100}\s\-\-module\so365_enum_office/ nocase ascii wide
                        $string16_Omnispray_offensive_tool_keyword = /\s\-\-type\sspray\s\-uf\s.{0,100}\s\-pf\s/ nocase ascii wide
                        $string17_Omnispray_offensive_tool_keyword = /\&passwd\=Winter2020\&ok\=Log\+In/
                        $string18_Omnispray_offensive_tool_keyword = /\/adfs\-spray\.py/ nocase ascii wide
                        $string19_Omnispray_offensive_tool_keyword = "/dafthack/MSOLSpray" nocase ascii wide
                        $string20_Omnispray_offensive_tool_keyword = /\/EASSniper\.ps1/ nocase ascii wide
                        $string21_Omnispray_offensive_tool_keyword = /\/o365_enum_activesync\.py/ nocase ascii wide
                        $string22_Omnispray_offensive_tool_keyword = /\/o365_enum_office\.py/ nocase ascii wide
                        $string23_Omnispray_offensive_tool_keyword = /\/o365_enum_onedrive\.py/ nocase ascii wide
                        $string24_Omnispray_offensive_tool_keyword = /\/o365_spray_activesync\.py/ nocase ascii wide
                        $string25_Omnispray_offensive_tool_keyword = /\/o365_spray_adfs\.py/ nocase ascii wide
                        $string26_Omnispray_offensive_tool_keyword = /\/o365_spray_msol\.py/ nocase ascii wide
                        $string27_Omnispray_offensive_tool_keyword = /\/Omnispray\.git/ nocase ascii wide
                        $string28_Omnispray_offensive_tool_keyword = /\/omnispray\.py/ nocase ascii wide
                        $string29_Omnispray_offensive_tool_keyword = /\/owa_enum_activesync\.py/ nocase ascii wide
                        $string30_Omnispray_offensive_tool_keyword = /\/owa_spray_activesync\.py/ nocase ascii wide
                        $string31_Omnispray_offensive_tool_keyword = /\/paloalto_enum_globalprotectportal\.py/ nocase ascii wide
                        $string32_Omnispray_offensive_tool_keyword = /\/paloalto_spray_globalprotectportal\.py/ nocase ascii wide
                        $string33_Omnispray_offensive_tool_keyword = /\[o365spray\]/ nocase ascii wide
                        $string34_Omnispray_offensive_tool_keyword = /\\adfs\-spray\.py/ nocase ascii wide
                        $string35_Omnispray_offensive_tool_keyword = /\\dafthack\\MSOLSpray/ nocase ascii wide
                        $string36_Omnispray_offensive_tool_keyword = /\\EASSniper\.ps1/ nocase ascii wide
                        $string37_Omnispray_offensive_tool_keyword = /\\o365_enum_activesync\.py/ nocase ascii wide
                        $string38_Omnispray_offensive_tool_keyword = /\\o365_enum_office\.py/ nocase ascii wide
                        $string39_Omnispray_offensive_tool_keyword = /\\o365_enum_onedrive\.py/ nocase ascii wide
                        $string40_Omnispray_offensive_tool_keyword = /\\o365_spray_activesync\.py/ nocase ascii wide
                        $string41_Omnispray_offensive_tool_keyword = /\\o365_spray_adfs\.py/ nocase ascii wide
                        $string42_Omnispray_offensive_tool_keyword = /\\o365_spray_msol\.py/ nocase ascii wide
                        $string43_Omnispray_offensive_tool_keyword = /\\omnispray\.py/ nocase ascii wide
                        $string44_Omnispray_offensive_tool_keyword = /\\Omnispray\-main/ nocase ascii wide
                        $string45_Omnispray_offensive_tool_keyword = /\\owa_enum_activesync\.py/ nocase ascii wide
                        $string46_Omnispray_offensive_tool_keyword = /\\owa_spray_activesync\.py/ nocase ascii wide
                        $string47_Omnispray_offensive_tool_keyword = /\\paloalto_enum_globalprotectportal\.py/ nocase ascii wide
                        $string48_Omnispray_offensive_tool_keyword = /\\paloalto_spray_globalprotectportal\.py/ nocase ascii wide
                        $string49_Omnispray_offensive_tool_keyword = "0f638c5cbc07c8c0f3f2343f5459af22e80e6a4abaeef14740454486903fcbb8" nocase ascii wide
                        $string50_Omnispray_offensive_tool_keyword = "0xZDH/Omnispray" nocase ascii wide
                        $string51_Omnispray_offensive_tool_keyword = /0xZDH\\Omnispray/ nocase ascii wide
                        $string52_Omnispray_offensive_tool_keyword = "130a517af6464f5a3d5e390b5fb90711029720b59cdeaab3c0300b4cf57227f9" nocase ascii wide
                        $string53_Omnispray_offensive_tool_keyword = "2d0029543e5781ba1136a85707546c7b3acafbaa56cf71e917c63cc2f7fea794" nocase ascii wide
                        $string54_Omnispray_offensive_tool_keyword = "3a1737f6fde0316cbc7552b8452384174908d9d124dd65016554a087455dd94e" nocase ascii wide
                        $string55_Omnispray_offensive_tool_keyword = "4459ea3ad77b52ee723e8e8db6cf46ac565fefef5126717f7fc64d596cd4eb67" nocase ascii wide
                        $string56_Omnispray_offensive_tool_keyword = "67d132f09b67e82cb54b941814c28737974165bcec5139909ed455fe97f2ab41" nocase ascii wide
                        $string57_Omnispray_offensive_tool_keyword = "6cc5645274bdacebf9b7d37b49f7440184722f021e13c407df2f7fc71c2b8e5f" nocase ascii wide
                        $string58_Omnispray_offensive_tool_keyword = "9e3a20cef67c034ac59b4793a8aa34cbdc7e130fe0ae791fe74059ba4ba0983d" nocase ascii wide
                        $string59_Omnispray_offensive_tool_keyword = "a1b2d9ea6e99d95f0e69e4aed2008823f52a7bbea2e1e1a102e8ab2fcc370829" nocase ascii wide
                        $string60_Omnispray_offensive_tool_keyword = "af190cf0778fc031a0db2eb2e36aaa0a09dea5495ce8a50d6e3eee439db3dc7a" nocase ascii wide
                        $string61_Omnispray_offensive_tool_keyword = "b6be69e72453d7363a2570495b36897124c72b2676351307f9d0d1b2a90f1b9d" nocase ascii wide
                        $string62_Omnispray_offensive_tool_keyword = "e336612e451075ecb75b27bd473aa21aba4f0a98df3cef57ad303894cce4f34b" nocase ascii wide
                        $string63_Omnispray_offensive_tool_keyword = "e953e1f2e64f00273fe92e24d434d7a6619bb873d43bef5dd330d42de591dc8d" nocase ascii wide
                        $string64_Omnispray_offensive_tool_keyword = /gist\.github\.com\/byt3bl33d3r\/19a48fff8fdc34cc1dd1f1d2807e1b7f/ nocase ascii wide
                        $string65_Omnispray_offensive_tool_keyword = "O365 Enumeration via ActiveSync module --" nocase ascii wide
                        $string66_Omnispray_offensive_tool_keyword = /O365\sEnumeration\svia\sOffice\.com\smodule\s\-\-/ nocase ascii wide
                        $string67_Omnispray_offensive_tool_keyword = "O365 Enumeration via OneDrive module --" nocase ascii wide
                        $string68_Omnispray_offensive_tool_keyword = "O365 Spraying via ActiveSync module --" nocase ascii wide
                        $string69_Omnispray_offensive_tool_keyword = "O365 Spraying via ADFS module --" nocase ascii wide
                        $string70_Omnispray_offensive_tool_keyword = "O365 Spraying via MSOL module --" nocase ascii wide
                        $string71_Omnispray_offensive_tool_keyword = /Omnispray\s\|\sModular\sEnumeration\sand\sPassword\sSpraying\sFramework/ nocase ascii wide
                        $string72_Omnispray_offensive_tool_keyword = "OWA Enumeration via ActiveSync timing module --" nocase ascii wide
                        $string73_Omnispray_offensive_tool_keyword = "OWA Spraying via ActiveSync module --" nocase ascii wide
                        $string74_Omnispray_offensive_tool_keyword = "Password spraying lockout policy reset time " nocase ascii wide
                        $string75_Omnispray_offensive_tool_keyword = "Password spraying the following passwords: " nocase ascii wide
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