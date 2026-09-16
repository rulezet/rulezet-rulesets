rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_3214ea252f2a_3430 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_3214ea252f2a25e018a03ee43ce952f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"

  strings:
    $s1 = "return \"UOe\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s2 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){" ascii
    $s3 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s4 = "(){return \"USf\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";" ascii
    $s5 = " \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Et\";})(),(fun" ascii
    $s6 = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}