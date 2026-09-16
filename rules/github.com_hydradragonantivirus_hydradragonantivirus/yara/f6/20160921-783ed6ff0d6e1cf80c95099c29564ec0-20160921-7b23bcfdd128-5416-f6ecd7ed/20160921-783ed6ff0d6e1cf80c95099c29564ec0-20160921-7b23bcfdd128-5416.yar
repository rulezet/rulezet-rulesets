rule _20160921_783ed6ff0d6e1cf80c95099c29564ec0_20160921_7b23bcfdd128_5416 {
  meta:
    description = "datamaliciousorder - from files 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_df51150cb4977f20502f85bfda11d939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash2       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash3       = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"

  strings:
    $s1 = "o\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s2 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Fv\";" ascii
    $s3 = "uck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo" ascii
    $s4 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"S" ascii
    $s5 = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}