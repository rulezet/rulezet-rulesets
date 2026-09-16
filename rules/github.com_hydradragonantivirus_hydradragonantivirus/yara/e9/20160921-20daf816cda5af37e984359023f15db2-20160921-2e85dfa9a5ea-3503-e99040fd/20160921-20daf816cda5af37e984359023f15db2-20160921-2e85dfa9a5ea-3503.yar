rule _20160921_20daf816cda5af37e984359023f15db2_20160921_2e85dfa9a5ea_3503 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash3       = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"

  strings:
    $s1 = "){return \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";}" ascii
    $s2 = "n \"Xw\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s3 = "(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(" ascii
    $s4 = "ction fuck(){return \"Tv\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return" ascii
    $s5 = "on fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return " ascii
    $s6 = "unction fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}