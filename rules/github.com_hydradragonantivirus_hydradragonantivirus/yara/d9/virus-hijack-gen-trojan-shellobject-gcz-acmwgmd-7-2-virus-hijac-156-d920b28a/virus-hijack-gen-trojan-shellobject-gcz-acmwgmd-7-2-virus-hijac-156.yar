rule _Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_7_2_Virus_Hijac_156 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aGN6KMb_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0q1@io_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@a8oUJio_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.kAZ@aCEmdoo_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.l8Z@aKTibuk_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.LuZ@aiy413e_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.LzZ@aWELKOd_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m9Z@aG4fkNb_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.muZ@aiy413e_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c19a4064f9ba6859fd14fb223c6a6d8c7b548352f33ae07be52e1d43be6fb004"
    hash2       = "1732c9bd06b7b849f34b16f3bcbc8d388a95eaf8bb6f48d8eb26f714aa6f6560"
    hash3       = "0a342fecc5080aadf02bff772fa9d0f99058d7a668ff5b4a419e249a3dd1ef47"
    hash4       = "658599b056579d9aa4ac668be5740841f0dc91ac32df732d9021644b126ee909"
    hash5       = "fdc6e0242fdefc527344b693087d51360b11663e59f4f930436bd3809be7d553"
    hash6       = "975d93ca0607c3cf27dab47cdf5a4a9b9ab7b76694afdabb90acc9f7d45bdf35"
    hash7       = "6a2de974c19ec849189a89fbf09851b7ffd1ca00ec294cae7dc2c561dfcfb146"
    hash8       = "ae82b599c8f8af0c1e42d2f93d0b97a2066c55a05de68c41d70c171593d958bd"
    hash9       = "0d11528290f09e9bd8433c2cd8a7a5505736b7cc403c22c21ef75ad93bff8e7b"
    hash10      = "65311b62c205830c8267644b585fc20b45cbf550d2e72c0054e700e3585f3328"
    hash11      = "f54f2085c2b27063cfe126a418867e95a89d5884bf5436841f74a6e4dfe0beaf"
    hash12      = "52e04767181f5e3fc800b23cbb50067ff234ffc60211c945b9854dede6acc614"
    hash13      = "e55ef04a8d60496e3b7c1952bffee49992145fa693507c523d67e9f49a11ebb3"
    hash14      = "9eea96a86ee8edad7ab68197d4bc0e62642697d1feabce5031dae4f1981a0817"
    hash15      = "08d10129a3e23aa52620c84f16f0d266e2c8e40d4d5f2680da91dd3a03f429d8"
    hash16      = "3a5b87aaf624bfa18224bbda4264f44234e35f728b592b208e3900225a546d18"
    hash17      = "1a277a5176b97114cb205028cb4aeebdada95fc80cb4e6fbaefcee193c4d0324"
    hash18      = "e49cc3940798fcedd43cc78e5fb016c5c4d13a14082e9dc15f416457268c6626"
    hash19      = "df3e21c46d92a2e94d1db64b6a635c0653efa4085f7249688e5ce55102119dec"
    hash20      = "c39695c9f4a6e1d205861f95eb4a9430f5fe4436b6b55d4ca65bf7db44b88e75"
    hash21      = "42dd93f893ab3883b1333d68ffe941bea87b0a21f858c7b1298590eaafabb740"
    hash22      = "af98772624b56471e6236d3a98f8fdaa9e2aac10244dd3acd396df8626e3edb7"

  strings:
    $x1  = "      <Command>%windir%\\system32\\rundll32.exe</Command>" fullword ascii
    $s2  = "      <Command>C:\\Windows\\system32\\sc.exe</Command>" fullword ascii
    $s3  = "        <Author>$(@%systemRoot%\\system32\\usocore.dll,-103)</Author>" fullword ascii
    $s4  = "      <Command>%systemroot%\\system32\\usoclient.exe</Command>" fullword ascii
    $s5  = "      <Command>%windir%\\system32\\compattelrunner.exe</Command>" fullword ascii
    $s6  = "      <Command>%systemroot%\\System32\\sihclient.exe</Command>" fullword ascii
    $s7  = "      <Command>%windir%\\system32\\cleanmgr.exe</Command>" fullword ascii
    $s8  = "      <Command>%systemroot%\\System32\\sc.exe</Command>" fullword ascii
    $s9  = "        <Description>$(@%systemRoot%\\system32\\usocore.dll,-106)</Description>" fullword ascii
    $s10 = "        <Source>$(@%systemRoot%\\system32\\usocore.dll,-104)</Source>" fullword ascii
    $s11 = "            <Command>%systemroot%\\system32\\MusNotification.exe</Command>" fullword ascii
    $s12 = "icability of healing actions, download necessary payloads to execute the actions, and execute healing actions.</Description>" fullword ascii
    $s13 = "    <Description>This daily task launches the SIH client (server-initiated healing) to detect and fix system components that are" ascii
    $s14 = "      <Command>%ProgramFiles%\\rempl\\disktoast.exe</Command>" fullword ascii
    $s15 = "      <Command>%ProgramFiles%\\rempl\\sedlauncher.exe</Command>" fullword ascii
    $s16 = "      <Command>%windir%\\UpdateAssistant\\UpdateAssistant.exe</Command>" fullword ascii
    $s17 = "<Task version=\"1.6\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" fullword ascii
    $s18 = "Failed to update the plugins payload" fullword wide
    $s19 = "    <Description>This task is used to start the Windows Update service when needed to perform scheduled operations such as scans" ascii
    $s20 = "ask fails to complete execution of applicable healing actions.  This boot task never goes online and does not evaluate applicabi" ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}