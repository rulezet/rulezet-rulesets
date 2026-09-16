rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_346ce24842d4_603 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"

  strings:
    $s1  = "(){return \"Nv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";}" ascii
    $s2  = ",(function f000(){return \"Nv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qa\";})(),(function f000(){re" ascii
    $s3  = "eturn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})()," ascii
    $s4  = "f000(){return \"Oh\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qa" ascii
    $s5  = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s6  = "\"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s7  = "f000(){return \"Qa\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br" ascii
    $s8  = "Xg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s9  = "ion f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s10 = "u\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s11 = "on f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"" ascii
    $s12 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"IA" ascii
    $s13 = "tion f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s14 = "ion f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"SEo\";})(),(function f000(){return" ascii
    $s15 = "00(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s16 = "Lp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s17 = " f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"" ascii
    $s18 = "n \"TKp\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})(),(fun" ascii
    $s19 = "nction f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){retu" ascii
    $s20 = "rn \"Sj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}