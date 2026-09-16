rule _20160921_093e56b49157ba4b6ba7d65a71037027_20160921_247788e339dc_3296 {
  meta:
    description = "datamaliciousorder - from files 20160921_093e56b49157ba4b6ba7d65a71037027.js, 20160921_247788e339dc74bbc88f76ce47a9ad41.js, 20160921_9addbf25729a1d4b42c35fbdfee2e294.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668a3627d0c7aef7745fe8887088d7f4ec88fb6a39c2470772085711e7db7c98"
    hash2       = "8d162c56b101895f4375e57c40971578d34e8dd1fdd076db93d245dcdade7a48"
    hash3       = "ec349891ac6c40b31c9f4aa62af04d8c399b64bf3db62ab4c615e3eb0931f1e6"
    hash4       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"

  strings:
    $s1 = "Bg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(functio" ascii
    $s2 = "function fuck(){return \"Vf\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){ret" ascii
    $s3 = "eturn \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})()" ascii
    $s4 = " \"CCb\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"LGo\";})(),(func" ascii
    $s5 = " \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(func" ascii
    $s6 = "on fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}