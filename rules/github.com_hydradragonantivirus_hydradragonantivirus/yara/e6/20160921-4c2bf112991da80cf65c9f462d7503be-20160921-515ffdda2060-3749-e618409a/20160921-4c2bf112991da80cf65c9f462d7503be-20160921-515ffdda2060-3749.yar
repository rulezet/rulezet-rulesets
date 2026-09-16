rule _20160921_4c2bf112991da80cf65c9f462d7503be_20160921_515ffdda2060_3749 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash2       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash3       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash4       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"
    hash5       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"

  strings:
    $s1 = "ck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";" ascii
    $s2 = "{return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})()" ascii
    $s3 = "nction fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retur" ascii
    $s4 = "nction fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return" ascii
    $s5 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii
    $s6 = "on fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}