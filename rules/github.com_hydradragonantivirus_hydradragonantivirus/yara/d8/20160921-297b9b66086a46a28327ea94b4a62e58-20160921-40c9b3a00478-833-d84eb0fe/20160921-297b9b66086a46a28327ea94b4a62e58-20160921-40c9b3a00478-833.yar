rule _20160921_297b9b66086a46a28327ea94b4a62e58_20160921_40c9b3a00478_833 {
  meta:
    description = "datamaliciousorder - from files 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash2       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash3       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1  = "),(function f000(){return \"UEg\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Sq\";})(),(function f000()" ascii
    $s2  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Um\";})(),(function f000(){return " ascii
    $s3  = "urn \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s4  = "00(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DYx" ascii
    $s5  = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Sq" ascii
    $s6  = ";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s7  = " \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s8  = "(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DYx\";" ascii
    $s9  = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})" ascii
    $s10 = "Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s11 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"" ascii
    $s12 = "(function f000(){return \"Qj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s13 = "tion f000(){return \"Tb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return" ascii
    $s14 = "nction f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){retur" ascii
    $s15 = "rn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(fu" ascii
    $s16 = "00(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn" ascii
    $s17 = "eturn \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Mt\";})()," ascii
    $s18 = "ion f000(){return \"Yv\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Mt\";})(),(function f000(){return " ascii
    $s19 = "urn \"MBb\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s20 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Mc\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}