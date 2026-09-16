rule _20160921_c42fb5c75aea2648513013ad2eed9aaf_20160921_dc1ff053e9dd_4054 {
  meta:
    description = "datamaliciousorder - from files 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash2       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"
    hash3       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = ",(function fuck(){return \"Oh\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){r" ascii
    $s2 = "unction fuck(){return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){ret" ascii
    $s3 = "ion fuck(){return \"Wo0\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s4 = "nction fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retur" ascii
    $s5 = "{return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"To\";})(" ascii
    $s6 = "n \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}