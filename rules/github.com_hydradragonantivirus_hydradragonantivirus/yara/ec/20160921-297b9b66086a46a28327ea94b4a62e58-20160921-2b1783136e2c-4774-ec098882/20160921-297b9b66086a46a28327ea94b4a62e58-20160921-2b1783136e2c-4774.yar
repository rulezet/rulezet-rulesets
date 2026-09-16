rule _20160921_297b9b66086a46a28327ea94b4a62e58_20160921_2b1783136e2c_4774 {
  meta:
    description = "datamaliciousorder - from files 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash2       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash3       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash4       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"

  strings:
    $s1 = ",(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000()" ascii
    $s2 = "n f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return " ascii
    $s3 = "{return \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";})(" ascii
    $s4 = "{return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";}" ascii
    $s5 = "0(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZGq\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}