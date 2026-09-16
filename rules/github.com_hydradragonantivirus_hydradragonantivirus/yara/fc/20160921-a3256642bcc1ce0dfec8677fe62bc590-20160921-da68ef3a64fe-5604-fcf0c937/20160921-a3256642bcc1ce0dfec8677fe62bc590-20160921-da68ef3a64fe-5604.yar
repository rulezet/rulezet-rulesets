rule _20160921_a3256642bcc1ce0dfec8677fe62bc590_20160921_da68ef3a64fe_5604 {
  meta:
    description = "datamaliciousorder - from files 20160921_a3256642bcc1ce0dfec8677fe62bc590.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"
    hash2       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"

  strings:
    $s1 = "Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(functi" ascii
    $s2 = "unction f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){ret" ascii
    $s3 = "000(){return \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn" ascii
    $s4 = "{return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(" ascii
    $s5 = "unction f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}