rule _20160921_ba8a9f239804499b5d1d2a06a862c1ca_20160921_c1ad71fea9bd_4038 {
  meta:
    description = "datamaliciousorder - from files 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"
    hash3       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "),(function f000(){return \"QDg\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"MJq\";})(),(function f000()" ascii
    $s2 = "ion f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s3 = "unction f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s4 = "n \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(fu" ascii
    $s5 = "f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj" ascii
    $s6 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}