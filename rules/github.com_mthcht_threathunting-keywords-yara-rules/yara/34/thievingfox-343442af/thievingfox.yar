rule ThievingFox
{
    meta:
        description = "Detection patterns for the tool 'ThievingFox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThievingFox"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --mobaxterm-poison-hkcr" nocase ascii wide
                        $string2 = " --mstsc-poison-hkcr" nocase ascii wide
                        $string3 = " --rdcman-poison-hkcr" nocase ascii wide
                        $string4 = /\sSuccessfully\shijacked\sKeePassXC\.exe/ nocase ascii wide
                        $string5 = /\sThievingFox\.py/ nocase ascii wide
                        $string6 = /\/logonuifox\.dll/ nocase ascii wide
                        $string7 = /\/mstscfox\.dll/ nocase ascii wide
                        $string8 = /\/rdcmanfox\.dll/ nocase ascii wide
                        $string9 = /\/ThievingFox\.git/ nocase ascii wide
                        $string10 = /\/ThievingFox\.py/ nocase ascii wide
                        $string11 = /\\consentfox\.dll/ nocase ascii wide
                        $string12 = /\\KeePassFox\.csproj/ nocase ascii wide
                        $string13 = /\\KeePassFox\.sln/ nocase ascii wide
                        $string14 = /\\logonuifox\.dll/ nocase ascii wide
                        $string15 = /\\mstscfox\.dll/ nocase ascii wide
                        $string16 = /\\rdcmanfox\.dll/ nocase ascii wide
                        $string17 = /\\ThievingFox\.py/ nocase ascii wide
                        $string18 = "28e90498456b5e0866fde4371f560e5673f75e761855b73b063eadaef39834d2" nocase ascii wide
                        $string19 = "6A5942A4-9086-408E-A9B4-05ABC34BFD58" nocase ascii wide
                        $string20 = "b99078f0abc00a579cf218f3ed1d1ca89fffd5c328239303bf98432732df00f0" nocase ascii wide
                        $string21 = "Compiling mstscax dll proxy" nocase ascii wide
                        $string22 = /Compiling\sproxy\sargon2\.dll/ nocase ascii wide
                        $string23 = "f6f082606e6725734c4ad3fef4e9d1ae5669ebab5c9085e6ab3b409793ca2000" nocase ascii wide
                        $string24 = "Found a sideloaded DLL, assuming injection already performed" nocase ascii wide
                        $string25 = /keepassxcfox\.dll/ nocase ascii wide
                        $string26 = /mobaxtermfox\.dll/ nocase ascii wide
                        $string27 = "Slowerzs/ThievingFox" nocase ascii wide
                        $string28 = /Successfully\shijacked\sKeePassXC\.exe/ nocase ascii wide
                        $string29 = /Successfully\spoisonned\sconsent\.exe/ nocase ascii wide
                        $string30 = /Successfully\spoisonned\sLogonUI\.exe/ nocase ascii wide
                        $string31 = "Successfully poisonned MobaXTerm" nocase ascii wide
                        $string32 = /Successfully\spoisonned\smstsc\.exe/ nocase ascii wide
                        $string33 = /Successfully\spoisonned\sRDCMan\.exe/ nocase ascii wide
                        $string34 = "Sucessfully performed AppDomainInjection for KeePass" nocase ascii wide
                        $string35 = /ThievingFox\.py\s/ nocase ascii wide
                        $string36 = "uploading mstscax proxy dll to " nocase ascii wide

    condition:
        any of them
}