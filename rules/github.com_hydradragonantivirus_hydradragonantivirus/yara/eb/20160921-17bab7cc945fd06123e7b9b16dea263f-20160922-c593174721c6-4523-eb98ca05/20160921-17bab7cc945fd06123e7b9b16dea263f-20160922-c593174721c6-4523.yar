rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160922_c593174721c6_4523 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"
    hash3       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Lp\";})(" ascii
    $s2 = "000(){return \"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg" ascii
    $s3 = "\"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(functi" ascii
    $s4 = "ion f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s5 = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DAp\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}