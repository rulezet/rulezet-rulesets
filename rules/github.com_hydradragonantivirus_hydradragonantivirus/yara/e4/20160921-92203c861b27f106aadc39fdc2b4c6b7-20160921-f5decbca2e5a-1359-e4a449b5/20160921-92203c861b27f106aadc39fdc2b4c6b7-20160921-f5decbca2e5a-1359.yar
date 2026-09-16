rule _20160921_92203c861b27f106aadc39fdc2b4c6b7_20160921_f5decbca2e5a_1359 {
  meta:
    description = "datamaliciousorder - from files 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_f5decbca2e5a35bbb5c42091c1b0c30e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash2       = "5fe03908bd7d860f1260a3264b2e10de3115d24242a095cf4c0b73e7934ce89e"

  strings:
    $s1  = ",(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Lp\";})(),(function f000(){" ascii
    $s2  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Uo\";})(),(" ascii
    $s3  = "(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){r" ascii
    $s4  = "(),(function f000(){return \"OMd\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"OMd\";})(),(function f000(" ascii
    $s5  = "f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TK" ascii
    $s6  = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"NBs\";})(),(function" ascii
    $s7  = "000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\"" ascii
    $s8  = "eturn \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SGs\";})()" ascii
    $s9  = "00(){return \"Br\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"Wh\";" ascii
    $s10 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Qj\";})()" ascii
    $s11 = "on f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"" ascii
    $s12 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"U" ascii
    $s13 = ")(),(function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Rh\";})(),(function f000()" ascii
    $s14 = "nction f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){ret" ascii
    $s15 = "rn \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}