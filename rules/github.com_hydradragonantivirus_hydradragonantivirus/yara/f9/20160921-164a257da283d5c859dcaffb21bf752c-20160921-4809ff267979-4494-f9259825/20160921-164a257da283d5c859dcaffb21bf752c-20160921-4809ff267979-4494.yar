rule _20160921_164a257da283d5c859dcaffb21bf752c_20160921_4809ff267979_4494 {
  meta:
    description = "datamaliciousorder - from files 20160921_164a257da283d5c859dcaffb21bf752c.js, 20160921_4809ff2679793c2b9af03e18ec3702ef.js, 20160921_56567a449e5ae44cd4a4e62bb55e63f3.js, 20160921_a0b892850e7511a70b7c95d4603de0d8.js, 20160921_fb2ccc1a635114bc23ea8a0a8413b110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36edb416a5f8703ead3fb8f8fbb7a0fb98ac21c559eb20558b33460ba9dfc9a0"
    hash2       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"
    hash3       = "e0950a0ccf96b116ed17c3fbaa99325e34f0b717e3e354bd1f926eee8465c6a7"
    hash4       = "0b5459eb728a278a131a764184d1d333fcd3fc212087b66d9cedce792b1a2d7a"
    hash5       = "c85e7d8e5c1682f21f2d8c9a0e1f6039d583d7eda8276ca9ed3ed381fbde9a7e"

  strings:
    $s1 = "uck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb" ascii
    $s2 = "n fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"N" ascii
    $s3 = "ion fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(" ascii
    $s5 = "\"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}