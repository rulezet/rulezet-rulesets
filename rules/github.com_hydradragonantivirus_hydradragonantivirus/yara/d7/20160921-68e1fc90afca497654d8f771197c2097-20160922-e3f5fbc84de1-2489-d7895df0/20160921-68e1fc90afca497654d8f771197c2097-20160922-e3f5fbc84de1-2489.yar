rule _20160921_68e1fc90afca497654d8f771197c2097_20160922_e3f5fbc84de1_2489 {
  meta:
    description = "datamaliciousorder - from files 20160921_68e1fc90afca497654d8f771197c2097.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash2       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "rn \"Vj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s2 = "f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn" ascii
    $s3 = "Nx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function" ascii
    $s4 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(functi" ascii
    $s5 = "unction f000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s6 = "ion f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return " ascii
    $s7 = ";})(),(function f000(){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br\";})(),(function f00" ascii
    $s8 = "rn \"Um\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}