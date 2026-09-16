rule _20160921_8aaa596582e26eec62319f01660d922b_20160921_f7b964e1d5b6_5507 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";}" ascii
    $s2 = "EZu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(functio" ascii
    $s3 = "unction f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){re" ascii
    $s4 = "nction f000(){return \"ZFe\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){retur" ascii
    $s5 = "unction f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Kw\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}