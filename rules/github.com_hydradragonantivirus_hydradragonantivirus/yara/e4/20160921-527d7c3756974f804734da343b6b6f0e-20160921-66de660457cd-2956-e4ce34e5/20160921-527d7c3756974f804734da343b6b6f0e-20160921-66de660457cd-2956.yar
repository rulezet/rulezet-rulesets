rule _20160921_527d7c3756974f804734da343b6b6f0e_20160921_66de660457cd_2956 {
  meta:
    description = "datamaliciousorder - from files 20160921_527d7c3756974f804734da343b6b6f0e.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"
    hash2       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"

  strings:
    $s1 = "nction f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f000(){ret" ascii
    $s2 = "return \"UOt\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})" ascii
    $s3 = "nction f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){retur" ascii
    $s4 = "Xg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s5 = "n\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function" ascii
    $s6 = "\"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(functi" ascii
    $s7 = "ction f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}