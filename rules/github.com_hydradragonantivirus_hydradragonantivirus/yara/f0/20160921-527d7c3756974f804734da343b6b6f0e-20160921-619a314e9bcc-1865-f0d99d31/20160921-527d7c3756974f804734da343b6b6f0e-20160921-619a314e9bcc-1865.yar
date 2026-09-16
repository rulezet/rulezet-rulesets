rule _20160921_527d7c3756974f804734da343b6b6f0e_20160921_619a314e9bcc_1865 {
  meta:
    description = "datamaliciousorder - from files 20160921_527d7c3756974f804734da343b6b6f0e.js, 20160921_619a314e9bcca286c046dff250b54b6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"
    hash2       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"

  strings:
    $s1  = "tion f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s2  = " f000(){return \"WIj\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"N" ascii
    $s3  = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Tn\";})(),(function f000(){r" ascii
    $s4  = "})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f00" ascii
    $s5  = "ction f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){retur" ascii
    $s6  = "unction f000(){return \"Oh\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s7  = "(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"KDh\";}" ascii
    $s8  = "Gn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function" ascii
    $s9  = "){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";" ascii
    $s10 = "on f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}