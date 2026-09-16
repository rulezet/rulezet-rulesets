rule _20160921_3362ac3903fc5c5d2da5d44e3afe884a_20160921_cdeac57ac549_4886 {
  meta:
    description = "datamaliciousorder - from files 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_cdeac57ac549120611856c7af0c490f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash2       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"

  strings:
    $s1 = "})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s2 = "00(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\"" ascii
    $s3 = "return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NBs\";})(" ascii
    $s4 = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Go\";})(),(f" ascii
    $s5 = "Ii\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}