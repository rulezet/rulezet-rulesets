rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_e59567324a54_3423 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"
    hash3       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = "00(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";}" ascii
    $s2 = "turn \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(fu" ascii
    $s3 = "(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){" ascii
    $s4 = ";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f0" ascii
    $s5 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s6 = "),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}