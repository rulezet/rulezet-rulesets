rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_a864250b4ae6_4639 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"

  strings:
    $s1 = " \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s2 = "f000(){return \"PTs\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Q" ascii
    $s3 = "on f000(){return \"HJm\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s4 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NYh" ascii
    $s5 = "return \"Ot\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}