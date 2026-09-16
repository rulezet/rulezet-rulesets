rule Virus_Hijack_Gen_Trojan_ShellObject_e4Y_a05ilOd_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4Y@a05ilOd_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d2f87f31c6fa91193bd501e00f35c3b6d31a287b996ecf36ba7a7f7540c498e"

  strings:
    $s1  = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; EmbeddedWB 14.52 from: http://www.bsalsa.com/ Embedd" ascii
    $s2  = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; EmbeddedWB 14.52 from: http://www.bsalsa.com/ Embedd" ascii
    $s3  = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; EmbeddedWB 14.52 from: http://www.bsalsa.com/ Embedd" ascii
    $s4  = "temp%02d.exe" fullword ascii
    $s5  = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; InfoPath.2; .NET CLR 2.0.50727; .NET CLR 3.0.4506.21" ascii
    $s6  = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; InfoPath.2; .NET CLR 2.0.50727; .NET CLR 3.0.4506.21" ascii
    $s7  = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; InfoPath.2; .NET CLR 2.0.50727; .NET CLR 3.0.4506.21" ascii
    $s8  = "temp%03d.zip" fullword ascii
    $s9  = "WEBPOST AGENT" fullword ascii
    $s10 = "@about:blank" fullword wide
    $s11 = "</a><body onLoad=\"" fullword ascii
    $s12 = "Accept: image/gif, image/jpeg, image/pjpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-excel, application/vn" ascii
    $s13 = "Accept: image/gif, image/jpeg, image/pjpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-excel, application/vn" ascii
    $s14 = "Accept: image/gif, image/jpeg, image/pjpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-excel, application/vn" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}