rule _20160921_3ca43590701fad2cb827b5edf3989d00_20160921_ad69715850fa_1706 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ca43590701fad2cb827b5edf3989d00.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"
    hash2       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1  = "a\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s2  = ")(),(function f000(){return \"MMz\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000" ascii
    $s3  = "return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii
    $s4  = "000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii
    $s5  = "0(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";}" ascii
    $s6  = "urn \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(fu" ascii
    $s7  = "urn \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Sj\";})(),(f" ascii
    $s8  = "f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s9  = "{return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})()" ascii
    $s10 = "tion f000(){return \"Ml\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s11 = "ion f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}