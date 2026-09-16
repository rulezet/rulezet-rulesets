rule _20160921_37277908f8111ad292e17a84927fe01d_20160921_b32c8921e339_2873 {
  meta:
    description = "datamaliciousorder - from files 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash2       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"

  strings:
    $s1 = "0(){return \"RPt\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s2 = "})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DNa\";})(),(function f00" ascii
    $s3 = "unction f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"PTs\";})(),(function f000(){retu" ascii
    $s4 = "PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(funct" ascii
    $s5 = "return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(" ascii
    $s6 = "){return \"Vj\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"DNa\";})(" ascii
    $s7 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}