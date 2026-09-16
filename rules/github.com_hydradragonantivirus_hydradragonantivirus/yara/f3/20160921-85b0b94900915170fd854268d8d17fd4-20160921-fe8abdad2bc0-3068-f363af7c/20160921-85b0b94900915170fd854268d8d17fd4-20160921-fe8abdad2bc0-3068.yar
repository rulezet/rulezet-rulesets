rule _20160921_85b0b94900915170fd854268d8d17fd4_20160921_fe8abdad2bc0_3068 {
  meta:
    description = "datamaliciousorder - from files 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash2       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1 = "(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){" ascii
    $s2 = " f000(){return \"Oe\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Vj" ascii
    $s3 = " \"RLk\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s4 = "n \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(fu" ascii
    $s5 = ")(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii
    $s6 = "n f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s7 = "0(){return \"KDh\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Tb\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}