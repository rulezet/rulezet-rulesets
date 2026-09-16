rule _20160921_ba8a9f239804499b5d1d2a06a862c1ca_20160921_ee1327bdf201_51 {
  meta:
    description = "datamaliciousorder - from files 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash2       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1  = "\"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s2  = "{return \"Yz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(" ascii
    $s3  = " \"Yv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s4  = "){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})" ascii
    $s5  = "n f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s6  = "eturn \"OUx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})()," ascii
    $s7  = "Pt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s8  = "{return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"XTn\";}" ascii
    $s9  = "0(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";" ascii
    $s10 = "eturn \"Go\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s11 = "return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})()" ascii
    $s12 = "000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Lo" ascii
    $s13 = "){return \"QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RVb\";}" ascii
    $s14 = "\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f" ascii
    $s15 = "turn \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s16 = "ion f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return" ascii
    $s17 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"" ascii
    $s18 = " f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"V" ascii
    $s19 = "ction f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return" ascii
    $s20 = "turn \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}