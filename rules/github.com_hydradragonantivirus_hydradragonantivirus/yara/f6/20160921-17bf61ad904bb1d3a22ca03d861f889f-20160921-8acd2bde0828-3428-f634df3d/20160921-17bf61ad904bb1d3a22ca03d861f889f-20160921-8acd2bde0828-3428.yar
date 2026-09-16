rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_8acd2bde0828_3428 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash3       = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"

  strings:
    $s1 = "tion fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s2 = "eturn \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s3 = "on fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s4 = "k(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\"" ascii
    $s5 = "rn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(f" ascii
    $s6 = "\"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}