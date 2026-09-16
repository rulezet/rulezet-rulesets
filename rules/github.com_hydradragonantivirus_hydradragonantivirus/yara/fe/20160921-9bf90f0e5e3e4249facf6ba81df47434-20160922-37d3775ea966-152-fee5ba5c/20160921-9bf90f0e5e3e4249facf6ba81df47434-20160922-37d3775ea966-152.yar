rule _20160921_9bf90f0e5e3e4249facf6ba81df47434_20160922_37d3775ea966_152 {
  meta:
    description = "datamaliciousorder - from files 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash2       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1  = "f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo" ascii
    $s2  = "n f000(){return \"IAa\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"" ascii
    $s3  = "unction f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){ret" ascii
    $s4  = "n \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(fun" ascii
    $s5  = "0(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";}" ascii
    $s6  = "Yz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(functio" ascii
    $s7  = "n \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Tn\";})(),(fu" ascii
    $s8  = "on f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s9  = "function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){ret" ascii
    $s10 = ";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f00" ascii
    $s11 = "urn \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(f" ascii
    $s12 = "f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do" ascii
    $s13 = "tion f000(){return \"Oe\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s14 = "){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})" ascii
    $s15 = "0(){return \"Uo\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qj\";}" ascii
    $s16 = "ction f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s17 = "SGs\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s18 = "on f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s19 = "n \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DYx\";})(),(fun" ascii
    $s20 = "n\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Do\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}