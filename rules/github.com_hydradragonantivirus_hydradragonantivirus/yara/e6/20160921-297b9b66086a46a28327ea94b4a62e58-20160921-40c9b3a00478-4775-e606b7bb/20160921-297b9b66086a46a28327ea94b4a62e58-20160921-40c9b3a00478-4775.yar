rule _20160921_297b9b66086a46a28327ea94b4a62e58_20160921_40c9b3a00478_4775 {
  meta:
    description = "datamaliciousorder - from files 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_b4c84c92954782bcf19013150a359ec6.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash2       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash3       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"
    hash4       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"

  strings:
    $s1 = "(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){re" ascii
    $s2 = "Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function" ascii
    $s3 = "{return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})()" ascii
    $s4 = "on f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return " ascii
    $s5 = "rn \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}