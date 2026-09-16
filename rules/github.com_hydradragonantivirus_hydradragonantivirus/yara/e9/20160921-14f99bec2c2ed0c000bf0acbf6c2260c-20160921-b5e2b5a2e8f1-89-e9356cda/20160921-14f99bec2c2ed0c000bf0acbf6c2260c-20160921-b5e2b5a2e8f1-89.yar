rule _20160921_14f99bec2c2ed0c000bf0acbf6c2260c_20160921_b5e2b5a2e8f1_89 {
  meta:
    description = "datamaliciousorder - from files 20160921_14f99bec2c2ed0c000bf0acbf6c2260c.js, 20160921_b5e2b5a2e8f104e719b3c6631c08f1f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224106b166fc0a998ec1d58e5d4a78c585bdeb76194d93210753d7d0f558c06b"
    hash2       = "8495e7e7fc77026b5e5681ac973eefb0561cb5cce78632996de59641ce00258e"

  strings:
    $s1  = "turn \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()," ascii
    $s2  = " \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(func" ascii
    $s3  = "on f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4  = "function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s5  = "ion f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s6  = "Gn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Wb\";})(),(functio" ascii
    $s7  = "j\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function " ascii
    $s8  = "return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})()," ascii
    $s9  = "nction f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Km\";})(),(function f000(){retu" ascii
    $s10 = "(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";}" ascii
    $s11 = ",(function f000(){return \"Mt\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){" ascii
    $s12 = ",(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){r" ascii
    $s13 = ",(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000()" ascii
    $s14 = " f000(){return \"NBs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s15 = "turn \"Yv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s16 = "ction f000(){return \"Km\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s17 = "){return \"Mc\";})(),(function f000(){return \"Yx\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br\";})()" ascii
    $s18 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s19 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZGq\";})(),(function f000(" ascii
    $s20 = "0(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}