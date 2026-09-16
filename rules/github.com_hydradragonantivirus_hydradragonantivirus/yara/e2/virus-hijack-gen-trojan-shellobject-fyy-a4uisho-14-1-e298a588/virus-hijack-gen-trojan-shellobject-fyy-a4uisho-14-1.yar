rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76d3a71509ae1f013be007c56de77ad9c9e15958fbdb5ff6a2f718e2da2420dd"

  strings:
    $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)" fullword ascii
    $s2 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.1)" fullword ascii
    $s3 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
    $s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 5.1)" fullword ascii
    $s5 = "Accept:-Language: zh-cn" fullword ascii
    $s6 = "Accept:  */*" fullword ascii
    $s7 = "Accept: image/gif image/x-xbitmap, image/jpeg,application/x-shockwave-flash" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}