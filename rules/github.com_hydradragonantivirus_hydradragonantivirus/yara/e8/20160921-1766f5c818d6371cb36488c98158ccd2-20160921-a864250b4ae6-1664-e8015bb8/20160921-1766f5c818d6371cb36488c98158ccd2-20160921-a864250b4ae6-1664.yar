rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_a864250b4ae6_1664 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"
    hash3       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"
    hash4       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1  = "{return \"WIj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"BQb\";})" ascii
    $s2  = " f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"V" ascii
    $s3  = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s4  = "turn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BMj\";})()," ascii
    $s5  = "tion f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return " ascii
    $s6  = "v\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Lp\";})(),(function" ascii
    $s7  = "urn \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"YTp\";})(),(" ascii
    $s8  = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return " ascii
    $s9  = "eturn \"ZIi\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})()" ascii
    $s10 = ")(),(function f000(){return \"PTs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qj\";})(),(function f000" ascii
    $s11 = "return \"DYs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}