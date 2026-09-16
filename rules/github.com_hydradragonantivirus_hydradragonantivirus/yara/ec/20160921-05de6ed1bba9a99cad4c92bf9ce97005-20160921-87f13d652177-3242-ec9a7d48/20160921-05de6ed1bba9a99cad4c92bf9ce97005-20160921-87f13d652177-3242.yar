rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_87f13d652177_3242 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_87f13d652177c2ccba1196dd341efb6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"

  strings:
    $s1 = ")(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"WIj\";})(),(function f000" ascii
    $s2 = "n f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s3 = "n f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s4 = "00(){return \"PTs\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\"" ascii
    $s5 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RLk\";})(),(function f00" ascii
    $s6 = "return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}