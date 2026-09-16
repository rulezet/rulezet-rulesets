rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_aqgEuSk_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1b504b8e34200d8029f6d75491d517e460162cb9df438257ee4ed85f61c18bc"

  strings:
    $s1  = "Hello, All your data in the company is encrypted and your important company data is backed up. I do not need money, I receive pa" ascii
    $s2  = "Hello, All your data in the company is encrypted and your important company data is backed up. I do not need money, I receive pa" ascii
    $s3  = " backed up after 7 days will be shared publicly on the internet and you will not be able to recover any of your encrypted data." fullword ascii
    $s4  = "yments from many companies every day and I deal with the encryption of many companies every day. More important than money is ti" ascii
    $s5  = "ave made for your company is very reasonable and not a big deal for you. If you do not pay, the data of the company that we have" ascii
    $s6  = ".?AV?$_Ref_count_obj2@V?$unordered_map@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$shared_ptr@VOptionDetail" ascii
    $s7  = " (default: \"\")" fullword ascii
    $s8  = "Option has no value" fullword ascii
    $s9  = "me for me. For this reason, I have time to inflate the number and bargain like other friends who do this business. The offer I h" ascii
    $s10 = " has no value" fullword ascii
    $s11 = "s@cxxopts@@@2@U?$hash@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@U?$equal_to@V?$basic_string@DU?$char_trai" ascii
    $s12 = ".?AV?$_Ref_count_obj2@V?$unordered_map@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$shared_ptr@VOptionDetail" ascii
    $s13 = "ts@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$sh" ascii
    $s14 = ".?AV?$_Ref_count_obj2@V?$standard_value@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@values@cxxopts@@@std@@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}