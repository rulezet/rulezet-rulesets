rule _20160921_093e56b49157ba4b6ba7d65a71037027_20160921_247788e339dc_4304 {
  meta:
    description = "datamaliciousorder - from files 20160921_093e56b49157ba4b6ba7d65a71037027.js, 20160921_247788e339dc74bbc88f76ce47a9ad41.js, 20160921_9addbf25729a1d4b42c35fbdfee2e294.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668a3627d0c7aef7745fe8887088d7f4ec88fb6a39c2470772085711e7db7c98"
    hash2       = "8d162c56b101895f4375e57c40971578d34e8dd1fdd076db93d245dcdade7a48"
    hash3       = "ec349891ac6c40b31c9f4aa62af04d8c399b64bf3db62ab4c615e3eb0931f1e6"
    hash4       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = "n \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(fun" ascii
    $s2 = ",(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){r" ascii
    $s3 = "\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function " ascii
    $s4 = "on fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"I" ascii
    $s5 = "\"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}