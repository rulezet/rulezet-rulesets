rule _20160921_2e85dfa9a5ea92be677fa9eceee4f8b1_20160921_e6977bb87c75_3584 {
  meta:
    description = "datamaliciousorder - from files 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash2       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"
    hash3       = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"

  strings:
    $s1 = "d\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function" ascii
    $s2 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(func" ascii
    $s3 = "tion fuck(){return \"MUs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s4 = "(function fuck(){return \"MUs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s5 = "n fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"U" ascii
    $s6 = "urn \"Xw\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}