import "pe"
rule icedid_032021_1 {
  meta:
    description = "files - file skull-x64.dat"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-03-21"
    hash1       = "59a2a5fae1c51afbbf1bf8c6eb0a65cb2b8575794e3890f499f8935035e633fc"

  strings:
    $s1 = "update" fullword ascii  
    $s2 = "PstmStr" fullword ascii
    $s3 = "mRsx0k/" fullword wide
    $s4 = "D$0lzK" fullword ascii
    $s5 = "A;Zts}H" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and
    (pe.imphash() == "67a065c05a359d287f1fed9e91f823d5" and (pe.exports("PstmStr") and pe.exports("update")) or all of them)
}