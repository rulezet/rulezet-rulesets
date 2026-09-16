rule Virus_Hijack_Gen_Trojan_ShellObject_r9Z_aipHmJk_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r9Z@aipHmJk_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f73b4876c46711da3e84bd57cd67898e5c285bbc0b8dd7e67203a9857ded3ef0"

  strings:
    $s1  = ".?AV?$sp_counted_impl_p@VTSingletonProcessorFactory@thrift@apache@@@detail@boost@@" fullword ascii
    $s2  = ".?AVTProcessorEventHandler@thrift@apache@@" fullword ascii
    $s3  = ".?AV?$sp_counted_impl_p@VQTrayServiceProcessor@qtray@@@detail@boost@@" fullword ascii
    $s4  = ".?AV?$sp_counted_impl_p@Vimpl@Mutex@concurrency@thrift@apache@@@detail@boost@@" fullword ascii
    $s5  = ".?AV?$sp_counted_impl_p@VTMyProcessorEventHandler@@@detail@boost@@" fullword ascii
    $s6  = "TPipeServer: client connection failed" fullword ascii
    $s7  = "Write to pipe failed" fullword ascii
    $s8  = "ScanMessageToCli failed: unknown result" fullword ascii
    $s9  = "SetAuthKey failed: unknown result" fullword ascii
    $s10 = "PostMessage failed: unknown result" fullword ascii
    $s11 = "AVMessageToCli failed: unknown result" fullword ascii
    $s12 = "PostCopyDataMessage failed: unknown result" fullword ascii
    $s13 = "GetTrayData failed: unknown result" fullword ascii
    $s14 = "UDiskMessageToCli failed: unknown result" fullword ascii
    $s15 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword wide
    $s16 = "!Beijing Qihu Technology Co., Ltd.1*0(" fullword ascii
    $s17 = "!Beijing Qihu Technology Co., Ltd.0" fullword ascii
    $s18 = " WHERE pathToSignedProductExe LIKE '%safemon\\\\QHSafeTray.exe'" fullword wide
    $s19 = "Qihoo 360 Technology Co. Ltd." fullword wide
    $s20 = "(C) Qihoo 360 Technology Co. Ltd., All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}