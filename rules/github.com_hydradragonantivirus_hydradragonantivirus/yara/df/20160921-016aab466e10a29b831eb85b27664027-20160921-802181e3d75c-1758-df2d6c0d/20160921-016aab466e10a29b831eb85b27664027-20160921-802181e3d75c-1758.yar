rule _20160921_016aab466e10a29b831eb85b27664027_20160921_802181e3d75c_1758 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_802181e3d75c3e2d045cebba97849683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"

  strings:
    $s1  = "n \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(fu" ascii
    $s2  = "tion f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s3  = ",(function f000(){return \"Yv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn\";})(),(function f000(){r" ascii
    $s4  = "){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})" ascii
    $s5  = "(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s6  = "GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(functio" ascii
    $s7  = ")(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000" ascii
    $s8  = "000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Ml" ascii
    $s9  = "turn \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s10 = "j\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}