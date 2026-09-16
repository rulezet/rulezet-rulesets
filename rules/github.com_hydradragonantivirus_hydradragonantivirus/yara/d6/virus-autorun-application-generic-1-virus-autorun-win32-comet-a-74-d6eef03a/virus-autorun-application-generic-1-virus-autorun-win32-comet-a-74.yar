rule _Virus_Autorun_Application_Generic_1_Virus_Autorun_Win32_Comet_A_74 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Application.Generic_1.vir, Virus.Autorun_Win32.Comet.A.vir, Virus.Autorun_Win32.Comet.A_1.vir, Virus.Autorun_Win32.Comet.A_2.vir, Virus.Autorun_Win32.Comet.A_3.vir, Virus.Autorun_Win32.Comet.A_4.vir, Virus.Autorun_Win32.Comet.A_5.vir, Virus.Autorun_Win32.Comet.A_6.vir, Virus.Autorun_Win32.Neshta.A_18.vir, Virus.Autorun_Win32.Neshta.A_21.vir, Virus.Autorun_Win32.Neshta.A_22.vir, Virus.Autorun_Win32.Neshta.A_44.vir, Virus.Autorun_Win32.Neshta.A_48.vir, Virus.Autorun_Win32.Neshta.A_52.vir, Virus.Autorun_Win32.Neshta.A_6.vir, Virus.Autorun_Win32.Viking.BB.vir, Virus.Delself_Win32.Neshta.A.vir, Virus.Delself_Win32.Neshta.A_1.vir, Virus.Delself_Win32.Neshta.A_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.v8Z@au0WBJh_3.vir, Virus.Infector_Win32.Neshta.A_2.vir, Virus.Infector_Win32.Neshta.A_3.vir, Virus.Infector_Win32.Neshta.A_4.vir, Virus.Injector _Application.Generic.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a9f41a4754074860cb8d34d972f410cdf062c3d3efb0c3e7e4de0413cc125bc"
    hash2       = "4b0ca81f4b9aab100d2dcbdc0e10f504abf3c4a86f7a319330f90b389f9f314c"
    hash3       = "5116bbbfb3f4d30c9dc854ec857e7ec5a5d7ecf830d3618c8b62b920ac3a0714"
    hash4       = "6f602a6e6bbcd7b664e041f22eb559c276eb9ceb2ef6aeac1ae7e513e20aff56"
    hash5       = "1bd6d53193b00c142b2df83f3f1454c2cb66139cfa53f824215d5c00dc92d978"
    hash6       = "be0d3215f6849abdd8933933b8c786f469919f48d0ba8129c6c8d60f2a446c6e"
    hash7       = "7d3cd5905c654a2a2155dbbdf62e904c7f80bd50d0c7c7acb16b364eb8f1a109"
    hash8       = "81b52956967d5429086e544b279c75a5366a2efdf43ef6e9bdb2b5bfa17c5e4b"
    hash9       = "ddb739cfce833cf4e4539b7a3a7c5088f3d739dd6d93181edfea412349f75853"
    hash10      = "bb62731afa68bfbad92eed82af13a8de3a54c0f2f507a0d1efe74576f795e42d"
    hash11      = "c534bbadc54dc2aeb5910a1a816e1e68876cf3b92589e40183fa99e70b38e999"
    hash12      = "29db7be00cbdb282b12d3e766cb910adf0c11904f848ba285c3d5d8ac60408e1"
    hash13      = "e681fc83bcf9577b2ab961cefe82fc118874ed22f76c1490e55dfd0a958b32f7"
    hash14      = "bf77441efaae986c73dfa9cdcdcd9f9f6cd45e9e7476ed4802f0cac0d4218ab0"
    hash15      = "c26e108781e9ae5ed30b1d2e315506e23e468d0ff377f6379951eac02bc7d4c1"
    hash16      = "98b774f4b9cc23b87cfb578d4e0adb79da19e43613f8e075c5d5af29fc24fd22"
    hash17      = "a7b5104521a95d6486bb59cf61f1e75741d70caa21925305e965f1678481d117"
    hash18      = "73683a190158492de56c05281186b7bb679359c56cf52899f72751461ecce4eb"
    hash19      = "5d1768fdab3a304d9036ca07f546618e92705895f822c2cddab22c92c7275113"
    hash20      = "52d97e788839e0f179824a95c466acba0e6aa376de1be28dbf73f417776207fc"
    hash21      = "22da49e50a81276e88eaecaa9718e340aab2e8b45485bd74d5b829de46f08d34"
    hash22      = "7b70a31512c7c99f95a94bf11f68c1fe2ff45f4eeb33a6c18de0fc03fadfcce8"
    hash23      = "b71185964e9cf345c553be78399b7d779af499f2c40299f450e1ff69ce80aa5c"
    hash24      = "2a163588a60a27a8b43398efb5f2b0b4378400db77f3d10cc67af7ab9b6eaece"

  strings:
    $s1  = "ExeInj Version -> " fullword ascii
    $s2  = "<<<<<<<<<<  SYSTEM LOG  >>>>>>>>>>" fullword ascii
    $s3  = "Keyboard Hook -> Active" fullword ascii
    $s4  = "Keyboard Hook -> Deactive" fullword ascii
    $s5  = "APP Copy -> " fullword ascii
    $s6  = "Infected Canceled -> " fullword ascii
    $s7  = "Directory Watcher -> Deactive" fullword ascii
    $s8  = "Auto Update -> Deactive" fullword ascii
    $s9  = "Drive Watcher Stop -> " fullword ascii
    $s10 = "TCP Client -> Pasif" fullword ascii
    $s11 = "Drive Watching -> " fullword ascii
    $s12 = "TCP Client -> Aktif" fullword ascii
    $s13 = "Drive Removed -> " fullword ascii
    $s14 = "Auto Mail Sender -> Deactive" fullword ascii
    $s15 = "USB Hooks -> Active" fullword ascii
    $s16 = "Auto Update -> Active" fullword ascii
    $s17 = "Drive Added -> " fullword ascii
    $s18 = "Directory Watcher -> Active" fullword ascii
    $s19 = "Update Res -> " fullword ascii
    $s20 = "Active -> " fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}