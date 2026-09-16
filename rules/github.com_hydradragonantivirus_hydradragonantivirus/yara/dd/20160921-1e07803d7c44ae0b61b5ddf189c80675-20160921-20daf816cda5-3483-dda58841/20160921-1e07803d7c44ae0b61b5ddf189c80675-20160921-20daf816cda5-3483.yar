rule _20160921_1e07803d7c44ae0b61b5ddf189c80675_20160921_20daf816cda5_3483 {
  meta:
    description = "datamaliciousorder - from files 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_460a913db46b41c41035cc210ed5fba0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash2       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash3       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"

  strings:
    $s1 = "(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Oh\";})" ascii
    $s2 = "fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv" ascii
    $s3 = "urn \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(f" ascii
    $s4 = ";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s5 = "(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){" ascii
    $s6 = "(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Az\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}