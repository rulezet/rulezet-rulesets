rule sig_20161207_bd6fe4be8e33408f6d213778cba09184 {
  meta:
    description = "datamaliciousorder - file 20161207_bd6fe4be8e33408f6d213778cba09184.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "541de7a6303fb72727afa6d7f9476cbf3bb0669b11c75dab23d2d7a96c46a4db"

  strings:
    $s1  = "return gettux;" fullword ascii
    $s2  = "return acegok;" fullword ascii
    $s3  = "return whexuro;" fullword ascii
    $s4  = "return apyn;" fullword ascii
    $s5  = "return kona;" fullword ascii
    $s6  = "function upjushy() {" fullword ascii
    $s7  = "function ahfahsosq() {" fullword ascii
    $s8  = "function pmehipta() {" fullword ascii
    $s9  = "return motgagi[2];" fullword ascii
    $s10 = "function esuz() {" fullword ascii
    $s11 = "function ddajhe() {" fullword ascii
    $s12 = "return esjacxez;" fullword ascii
    $s13 = "return yjpudy;" fullword ascii
    $s14 = "return ewesb;" fullword ascii
    $s15 = "return abanuzd;" fullword ascii
    $s16 = "function bxukbyth() {" fullword ascii
    $s17 = "return tamgo;" fullword ascii
    $s18 = "return vuhwixso[0];" fullword ascii
    $s19 = "return amyklu;" fullword ascii
    $s20 = "return yqul;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}