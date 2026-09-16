rule _20160921_da68ef3a64fe9761a5f4505bcaef8f82_20160921_dff46b67b973_2575 {
  meta:
    description = "datamaliciousorder - from files 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"
    hash2       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1 = "ction f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii
    $s2 = "return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DYx\";})(" ascii
    $s3 = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DNa\";})(),(function" ascii
    $s4 = "n \"Qa\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s5 = "rn \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s6 = "unction f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){retu" ascii
    $s7 = ")(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(" ascii
    $s8 = "ion f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}