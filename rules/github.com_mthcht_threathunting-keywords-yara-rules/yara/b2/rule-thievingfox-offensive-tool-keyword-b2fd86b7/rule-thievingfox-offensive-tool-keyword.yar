rule rule_ThievingFox_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ThievingFox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThievingFox"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ThievingFox_offensive_tool_keyword = " --mobaxterm-poison-hkcr" nocase ascii wide
                        $string2_ThievingFox_offensive_tool_keyword = " --mstsc-poison-hkcr" nocase ascii wide
                        $string3_ThievingFox_offensive_tool_keyword = " --rdcman-poison-hkcr" nocase ascii wide
                        $string4_ThievingFox_offensive_tool_keyword = /\sSuccessfully\shijacked\sKeePassXC\.exe/ nocase ascii wide
                        $string5_ThievingFox_offensive_tool_keyword = /\sThievingFox\.py/ nocase ascii wide
                        $string6_ThievingFox_offensive_tool_keyword = /\/logonuifox\.dll/ nocase ascii wide
                        $string7_ThievingFox_offensive_tool_keyword = /\/mstscfox\.dll/ nocase ascii wide
                        $string8_ThievingFox_offensive_tool_keyword = /\/rdcmanfox\.dll/ nocase ascii wide
                        $string9_ThievingFox_offensive_tool_keyword = /\/ThievingFox\.git/ nocase ascii wide
                        $string10_ThievingFox_offensive_tool_keyword = /\/ThievingFox\.py/ nocase ascii wide
                        $string11_ThievingFox_offensive_tool_keyword = /\\consentfox\.dll/ nocase ascii wide
                        $string12_ThievingFox_offensive_tool_keyword = /\\KeePassFox\.csproj/ nocase ascii wide
                        $string13_ThievingFox_offensive_tool_keyword = /\\KeePassFox\.sln/ nocase ascii wide
                        $string14_ThievingFox_offensive_tool_keyword = /\\logonuifox\.dll/ nocase ascii wide
                        $string15_ThievingFox_offensive_tool_keyword = /\\mstscfox\.dll/ nocase ascii wide
                        $string16_ThievingFox_offensive_tool_keyword = /\\rdcmanfox\.dll/ nocase ascii wide
                        $string17_ThievingFox_offensive_tool_keyword = /\\ThievingFox\.py/ nocase ascii wide
                        $string18_ThievingFox_offensive_tool_keyword = "28e90498456b5e0866fde4371f560e5673f75e761855b73b063eadaef39834d2" nocase ascii wide
                        $string19_ThievingFox_offensive_tool_keyword = "6A5942A4-9086-408E-A9B4-05ABC34BFD58" nocase ascii wide
                        $string20_ThievingFox_offensive_tool_keyword = "b99078f0abc00a579cf218f3ed1d1ca89fffd5c328239303bf98432732df00f0" nocase ascii wide
                        $string21_ThievingFox_offensive_tool_keyword = "Compiling mstscax dll proxy" nocase ascii wide
                        $string22_ThievingFox_offensive_tool_keyword = /Compiling\sproxy\sargon2\.dll/ nocase ascii wide
                        $string23_ThievingFox_offensive_tool_keyword = "f6f082606e6725734c4ad3fef4e9d1ae5669ebab5c9085e6ab3b409793ca2000" nocase ascii wide
                        $string24_ThievingFox_offensive_tool_keyword = "Found a sideloaded DLL, assuming injection already performed" nocase ascii wide
                        $string25_ThievingFox_offensive_tool_keyword = /keepassxcfox\.dll/ nocase ascii wide
                        $string26_ThievingFox_offensive_tool_keyword = /mobaxtermfox\.dll/ nocase ascii wide
                        $string27_ThievingFox_offensive_tool_keyword = "Slowerzs/ThievingFox" nocase ascii wide
                        $string28_ThievingFox_offensive_tool_keyword = /Successfully\shijacked\sKeePassXC\.exe/ nocase ascii wide
                        $string29_ThievingFox_offensive_tool_keyword = /Successfully\spoisonned\sconsent\.exe/ nocase ascii wide
                        $string30_ThievingFox_offensive_tool_keyword = /Successfully\spoisonned\sLogonUI\.exe/ nocase ascii wide
                        $string31_ThievingFox_offensive_tool_keyword = "Successfully poisonned MobaXTerm" nocase ascii wide
                        $string32_ThievingFox_offensive_tool_keyword = /Successfully\spoisonned\smstsc\.exe/ nocase ascii wide
                        $string33_ThievingFox_offensive_tool_keyword = /Successfully\spoisonned\sRDCMan\.exe/ nocase ascii wide
                        $string34_ThievingFox_offensive_tool_keyword = "Sucessfully performed AppDomainInjection for KeePass" nocase ascii wide
                        $string35_ThievingFox_offensive_tool_keyword = /ThievingFox\.py\s/ nocase ascii wide
                        $string36_ThievingFox_offensive_tool_keyword = "uploading mstscax proxy dll to " nocase ascii wide

    condition:
        any of them
}