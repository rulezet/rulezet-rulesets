import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_5_2_Virus_Hijack_306 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@amWqEpo_9.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aSWq7Qp_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aKzulAn_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c715436301979b8fe283f9064e2c2722b8237b902604c2359388c1c55f95a8f6"
    hash2       = "e55d46a52c7c393032375aa81885b104c2cf2c6a5f4a45f616bc019aa599971b"
    hash3       = "7f810ea74daeeb211dca58e1c256af4ffe01f7a17f9a3df161505f05549e5f8e"
    hash4       = "e235c59ee919330f8714453b403c4acc854d66d5c1b6773d37a9c2b017938df6"
    hash5       = "d32023d7ab0741c0085cba4eeaf83d8d962e5ab4648deee2682aebe351d516f9"

  strings:
    $s1  = "?GetVersion@Bundle@cppmicroservices@@QEBA?AVBundleVersion@2@XZ" fullword ascii
    $s2  = " SGX AESM_The system services management agent for Intel" fullword wide
    $s3  = "?GetBundleContext@Bundle@cppmicroservices@@QEBA?AVBundleContext@2@XZ" fullword ascii
    $s4  = "The AESM service is starting. PSW Version: %s" fullword wide
    $s5  = "The AESM service is stopping or pausing." fullword wide
    $s6  = "Failed to create AESM service event" fullword wide
    $s7  = "Failed to start AESM service" fullword wide
    $s8  = ".?AV?$Singleton@VAESMLogic@@@@" fullword ascii
    $s9  = "?GetInterfaceId@ServiceReferenceBase@cppmicroservices@@QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ" fullword ascii
    $s10 = "?GetBundles@BundleContext@cppmicroservices@@QEBA?AV?$vector@VBundle@cppmicroservices@@V?$allocator@VBundle@cppmicroservices@@@st" ascii
    $s11 = "?GetDemangledName@detail@cppmicroservices@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AEBVtype_info@@@Z" fullword ascii
    $s12 = "?GetServiceReference@BundleContext@cppmicroservices@@QEAA?AV?$ServiceReference@X@2@AEBV?$basic_string@DU?$char_traits@D@std@@V?$" ascii
    $s13 = "?GetBundles@BundleContext@cppmicroservices@@QEBA?AV?$vector@VBundle@cppmicroservices@@V?$allocator@VBundle@cppmicroservices@@@st" ascii
    $s14 = "?Start@Bundle@cppmicroservices@@QEAAXXZ" fullword ascii
    $s15 = "?Stop@Bundle@cppmicroservices@@QEAAXXZ" fullword ascii
    $s16 = "?Init@Framework@cppmicroservices@@QEAAXXZ" fullword ascii
    $s17 = "?WaitForStop@Framework@cppmicroservices@@QEAA?AVFrameworkEvent@2@AEBV?$duration@_JU?$ratio@$00$0DOI@@std@@@chrono@std@@@Z" fullword ascii
    $s18 = "%s. PSW Version: %s" fullword wide
    $s19 = "AESMRpcServerStart failed with error=0x%x" fullword wide
    $s20 = "CurVer = s 'SGX.AESM.1'" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "0b01da733c3b842263c2201c4b62ee7e" and (8 of them)
    ) or (all of them)
}