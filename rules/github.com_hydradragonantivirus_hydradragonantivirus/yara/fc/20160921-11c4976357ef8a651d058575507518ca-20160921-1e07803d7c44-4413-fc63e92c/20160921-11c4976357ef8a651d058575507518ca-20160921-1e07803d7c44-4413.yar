rule _20160921_11c4976357ef8a651d058575507518ca_20160921_1e07803d7c44_4413 {
  meta:
    description = "datamaliciousorder - from files 20160921_11c4976357ef8a651d058575507518ca.js, 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_460a913db46b41c41035cc210ed5fba0.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"
    hash2       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash3       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash4       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"
    hash5       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"

  strings:
    $s1 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(functi" ascii
    $s2 = "ck(){return \"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx" ascii
    $s3 = "function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s4 = "n fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"" ascii
    $s5 = "unction fuck(){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}