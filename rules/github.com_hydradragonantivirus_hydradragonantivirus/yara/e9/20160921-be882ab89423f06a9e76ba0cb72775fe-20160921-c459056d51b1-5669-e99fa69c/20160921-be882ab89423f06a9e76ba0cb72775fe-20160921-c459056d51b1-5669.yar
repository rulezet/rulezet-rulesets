rule _20160921_be882ab89423f06a9e76ba0cb72775fe_20160921_c459056d51b1_5669 {
  meta:
    description = "datamaliciousorder - from files 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_c459056d51b1a4ea3176139800021b35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash2       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"

  strings:
    $s1 = "n \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s2 = "ion f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s3 = "return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"SGs\";})()" ascii
    $s4 = "ction f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s5 = "ction f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}