rule _20160921_164a257da283d5c859dcaffb21bf752c_20160921_378cbd2e2764_4493 {
  meta:
    description = "datamaliciousorder - from files 20160921_164a257da283d5c859dcaffb21bf752c.js, 20160921_378cbd2e27643682973c633e59454f9f.js, 20160921_56567a449e5ae44cd4a4e62bb55e63f3.js, 20160921_9b80c329004df146d978cb7b31b22c05.js, 20160921_a0b892850e7511a70b7c95d4603de0d8.js, 20160921_fb2ccc1a635114bc23ea8a0a8413b110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36edb416a5f8703ead3fb8f8fbb7a0fb98ac21c559eb20558b33460ba9dfc9a0"
    hash2       = "8ce016002e44e1fbf4624122138e5a8b0261aff6487c52da0d644398da46a896"
    hash3       = "e0950a0ccf96b116ed17c3fbaa99325e34f0b717e3e354bd1f926eee8465c6a7"
    hash4       = "d0ec644cd7307cbd280d369539e9834d3ad2ba0909b631b5a3640f8f6a1105d1"
    hash5       = "0b5459eb728a278a131a764184d1d333fcd3fc212087b66d9cedce792b1a2d7a"
    hash6       = "c85e7d8e5c1682f21f2d8c9a0e1f6039d583d7eda8276ca9ed3ed381fbde9a7e"

  strings:
    $s1 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})()," ascii
    $s2 = "on fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s3 = "Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(functi" ascii
    $s4 = "function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){ret" ascii
    $s5 = "urn \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}