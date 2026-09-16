rule _Virus_Hijack_Gen_Trojan_ShellObject_j8X_aOWk52b_8_1_Virus_Hijac_41 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.j8X@aOWk52b_8_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ae0D4Vj_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ai6MB5n_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.J8Z@ame9q4b_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24b645abc09a6674a5d17820a41e3bfe1237ae30da25cab97be54d652f6fd9db"
    hash2       = "79a2e8ca12d85114df7e1f8c6490220ad0128e462aaa26cdd580a0ad6aa87f98"
    hash3       = "dc2670f1082f73b5fae07b86e8c35433ef505ce3de34a7a2039f27533139335a"
    hash4       = "990ec0811faa820e58006989d75d485a6a1acc41f51e5d6311e3bdb3ea1c0b9b"

  strings:
    $s1  = "c7e18-k3dF0e=W7n6uo33Ursh_2oWdof11C lu6  S.i3 oib 2l~  pick -" fullword ascii
    $s2  = "bread " fullword wide
    $s3  = "ZOON}k2" fullword ascii
    $s4  = "Own Fillsure does" fullword wide
    $s5  = "Copyright 2006, Own Fillsure does" fullword wide
    $s6  = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s7  = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s8  = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s9  = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s10 = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s11 = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s12 = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s13 = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s14 = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s15 = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s16 = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s17 = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s18 = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii
    $s19 = "            <Resolve package=\"WUClient-SelfUpdate-Aux-AuxComp~31bf3856ad364e35~x86~ru-RU~7.6.7600.320\" update=\"Aux\"/>" fullword ascii
    $s20 = "            <Install package=\"Microsoft-Windows-Common-Modem-Drivers-Package~31bf3856ad364e35~x86~~6.1.7600.16385\" update=\"IN" ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}