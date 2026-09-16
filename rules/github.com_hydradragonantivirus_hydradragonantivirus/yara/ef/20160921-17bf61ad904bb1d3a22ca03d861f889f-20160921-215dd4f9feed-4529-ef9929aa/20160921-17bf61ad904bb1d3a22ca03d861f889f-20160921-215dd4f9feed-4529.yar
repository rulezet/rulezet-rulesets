rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_215dd4f9feed_4529 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"

  strings:
    $s1 = "(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";}" ascii
    $s2 = "urn \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s3 = "n fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"" ascii
    $s4 = "eturn \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s5 = "uck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}