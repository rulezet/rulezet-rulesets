rule _20160921_7b23bcfdd1289634cd9a4c73f4cbb144_20160921_ce9aea7615ba_5435 {
  meta:
    description = "datamaliciousorder - from files 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js, 20160921_df51150cb4977f20502f85bfda11d939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash2       = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"
    hash3       = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"

  strings:
    $s1 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi" ascii
    $s2 = "),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck()" ascii
    $s3 = " \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(fun" ascii
    $s4 = ";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fu" ascii
    $s5 = "n \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}