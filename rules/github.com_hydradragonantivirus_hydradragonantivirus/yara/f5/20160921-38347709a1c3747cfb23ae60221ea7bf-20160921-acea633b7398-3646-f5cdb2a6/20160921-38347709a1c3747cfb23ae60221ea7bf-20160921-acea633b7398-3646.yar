rule _20160921_38347709a1c3747cfb23ae60221ea7bf_20160921_acea633b7398_3646 {
  meta:
    description = "datamaliciousorder - from files 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_acea633b73985995ce9764bf94db0972.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash2       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"

  strings:
    $s1 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"" ascii
    $s2 = "ck(){return \"DWe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\"" ascii
    $s3 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return " ascii
    $s4 = "Pz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function" ascii
    $s5 = " fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"C" ascii
    $s6 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"GWo\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}