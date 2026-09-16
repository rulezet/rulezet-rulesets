rule _Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_197_2_Tro_316 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_197_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_198_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_20_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_2_2.vir, Virus.Delself_Gen.Variant.Zusy.548289.vir, Virus.Delself_Trojan.GenericKD.37603403.vir, Virus.Delself_Trojan.GenericKD.37603403_1.vir, Virus.Delself_Trojan.GenericKD.37603403_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_49_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSW@aaT6Wyj_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSW@aaT6Wyj_8_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_130_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_131_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_134_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_135_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_138_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_13_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_143_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dedfd011a7b895f1e504957fc594364f08edefc0fa4943f3ab5cf5dec559ff5"
    hash2       = "8853ec7847140576a8265fcdd473ea56f8a770b6babf1faec9440da5c22b25d6"
    hash3       = "a54af397eee4f60a6b517204688aa6245bc5e0ddb41978d9c0119293a1c3d006"
    hash4       = "64a2d2bc9dfe86000b1bfbd694d79e4b41d0c99c6098ac5969ca903f17042e6d"
    hash5       = "fe8432b83896e299c511400d5c9eba147f70535e2ef198f53dd68116e5653a53"
    hash6       = "b75c3d98532794821f8863e82a33a1062b9787483c5706236cf9c08a8471bb08"
    hash7       = "f0bd359c94f21fd411371045750e4ba78d746edf2485e92d0aea031d207baf9e"
    hash8       = "0f8955cd289386b1c63e3937ff296a9d1281ca2b743192bb0696b43c3d6f0788"
    hash9       = "fa10104338c2676e6b123a8ca215e9162a9bbad878270441371efc17bf8a1dcd"
    hash10      = "b53342bc75a6f82f85bf77c61a9cbc788dd424829dbe30278e662bc1edb3f220"
    hash11      = "8921e1bcdba2c428fb61489a2d4c83af7c59ea4e0cf122454d86d6052d010a0b"
    hash12      = "7931413537ac650b9b18eda95c12d9e075638a098f0554bc5150232c83838837"
    hash13      = "4c0445dfa7bab7cea20836ae7b3ff2d43152095d619100064df1a096747d5f79"
    hash14      = "109cf0aff54303771c99f720aa9b726240c10faba676e6a0f4dd3cd50319c6e2"
    hash15      = "909cdc17edae4ee5f3033dc9605064ef624d4a21da2545f145055d4e9606d598"
    hash16      = "a8e4f83daa6fca49b28d19b6863022f5870d0931aadaf264323da833fb9c354e"
    hash17      = "7dfbfb66d25258afaccf3ac094c3086e0c3f5dcd659a624b319550133af16b24"
    hash18      = "67ed1ec3bf902bb8645a9b81c9061ec312b3ec2bcb862d34bec54d0d14e8d2fc"

  strings:
    $x1  = "echo y|cacls %systemroot%\\system32\\termsrv.dll /C /G Administrators:F SYSTEM:F Everyone:Fc:\\windows\\system32\\termsrv.dll" fullword ascii
    $s2  = "set procs=wmi.execquery(\"select * from win32_process\")    " fullword ascii
    $s3  = "wmic /namespace:\\\\root\\cimv2\\terminalservices path win32_tsgeneralsetting where (TerminalName ='RDP-Tcp') call setuserauthen" ascii
    $s4  = "wmic /namespace:\\\\root\\cimv2\\terminalservices path win32_tsgeneralsetting where (TerminalName ='RDP-Tcp') call setuserauthen" ascii
    $s5  = "REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal\" \"Server /v fDenyTSConnections /t REG_DWORD /d 0 /f" fullword ascii
    $s6  = "wmic /namespace:\\\\root\\cimv2\\terminalservices path win32_terminalservicesetting where (__CLASS != \"\") call setallowtsconne" ascii
    $s7  = "wmic /namespace:\\\\root\\cimv2\\terminalservices path win32_terminalservicesetting where (__CLASS != \"\") call setallowtsconne" ascii
    $s8  = "net start termservice /y" fullword ascii
    $s9  = "net user Admin$ remote /add" fullword ascii
    $s10 = "net start termservice" fullword ascii
    $s11 = "net start dcomlaunch" fullword ascii
    $s12 = "CMD /C shutdown -a" fullword ascii
    $s13 = "net user Admin$ /activ:yes" fullword ascii
    $s14 = "net stop termservice  /y" fullword ascii
    $s15 = "explorer http://www." fullword ascii
    $s16 = "dim wmi,proc,procs,proname,flag,WshShell    " fullword ascii
    $s17 = "Anonymous " fullword ascii
    $s18 = "Install time:" fullword ascii
    $s19 = "{Page Up}" fullword ascii
    $s20 = "{Page Down}" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}