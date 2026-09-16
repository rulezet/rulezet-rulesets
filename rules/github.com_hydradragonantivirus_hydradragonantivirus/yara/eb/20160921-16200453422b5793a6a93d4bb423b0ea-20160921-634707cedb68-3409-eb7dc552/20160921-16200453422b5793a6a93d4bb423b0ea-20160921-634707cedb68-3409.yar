rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_634707cedb68_3409 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_634707cedb68c58923df5bdbd700c1bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"

  strings:
    $s1 = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Vj\";})(),(fun" ascii
    $s2 = "000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Qz" ascii
    $s3 = "00(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tb" ascii
    $s4 = "){return \"PTs\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})" ascii
    $s5 = "function f000(){return \"Yv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){ret" ascii
    $s6 = "function f000(){return \"DYs\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"XTn\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}