rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_dd666c66b3f1_1383 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1  = "eturn \"BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})()," ascii
    $s2  = "{return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})" ascii
    $s3  = " \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(func" ascii
    $s4  = "n f000(){return \"MKa\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(f" ascii
    $s6  = "i\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function" ascii
    $s7  = "})(),(function f000(){return \"Wh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s8  = "){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";}" ascii
    $s9  = ";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f00" ascii
    $s10 = "(function f000(){return \"Mu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){ret" ascii
    $s11 = "nction f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii
    $s12 = "urn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s13 = "ction f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Iq\";})(),(function f000(){retur" ascii
    $s14 = "\"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}