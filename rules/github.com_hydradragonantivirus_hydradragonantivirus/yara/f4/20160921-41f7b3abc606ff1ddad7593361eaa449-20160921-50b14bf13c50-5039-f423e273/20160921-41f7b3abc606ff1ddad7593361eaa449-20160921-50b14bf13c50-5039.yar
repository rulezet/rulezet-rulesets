rule _20160921_41f7b3abc606ff1ddad7593361eaa449_20160921_50b14bf13c50_5039 {
  meta:
    description = "datamaliciousorder - from files 20160921_41f7b3abc606ff1ddad7593361eaa449.js, 20160921_50b14bf13c50bc31f09e3c583e1d422d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e06a7234c6522ba26a61e46d13312e1063594b0e33bec9fae49d2dc4b77c28"
    hash2       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"

  strings:
    $s1 = "\"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s2 = "{return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(" ascii
    $s3 = "Us\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function" ascii
    $s4 = "ion fuck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return " ascii
    $s5 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Wo0\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}