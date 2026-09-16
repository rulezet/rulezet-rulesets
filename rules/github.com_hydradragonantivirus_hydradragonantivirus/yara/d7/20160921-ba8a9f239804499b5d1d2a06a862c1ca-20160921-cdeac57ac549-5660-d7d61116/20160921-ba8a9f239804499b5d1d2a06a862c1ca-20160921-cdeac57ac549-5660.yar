rule _20160921_ba8a9f239804499b5d1d2a06a862c1ca_20160921_cdeac57ac549_5660 {
  meta:
    description = "datamaliciousorder - from files 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_cdeac57ac549120611856c7af0c490f6.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash2       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"
    hash3       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "unction f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s2 = "unction f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s3 = "function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Ml\";})(),(function f000(){re" ascii
    $s4 = "000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs" ascii
    $s5 = "TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}