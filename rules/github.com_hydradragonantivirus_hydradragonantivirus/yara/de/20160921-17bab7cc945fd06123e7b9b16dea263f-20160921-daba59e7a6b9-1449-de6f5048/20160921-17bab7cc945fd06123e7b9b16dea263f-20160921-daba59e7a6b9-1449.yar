rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_daba59e7a6b9_1449 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"
    hash3       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1  = "{return \"Tb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MMz\";})" ascii
    $s2  = "ion f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RLk\";})(),(function f000(){return" ascii
    $s3  = "eturn \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MDb\";})()" ascii
    $s4  = "urn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MBb\";})()," ascii
    $s5  = "})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f00" ascii
    $s6  = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Nv\";})(),(func" ascii
    $s7  = "Xg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"SEo\";})(),(functi" ascii
    $s8  = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Um\";})(),(function " ascii
    $s9  = "function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mt\";})(),(function f000(){retu" ascii
    $s10 = "return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s11 = "n f000(){return \"Yz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"" ascii
    $s12 = "on f000(){return \"KDh\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s13 = "turn \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}