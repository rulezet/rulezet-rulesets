rule _20160921_4c2bf112991da80cf65c9f462d7503be_20160921_515ffdda2060_5126 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_531eaafa1b0a00d86f2203fbd289dd63.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js, 20160921_e07d4e2b80172d933515ba35e18c07eb.js, 20160921_e53844f4bb18305322896332fbd017e8.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash2       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash3       = "d28500022264ce61d9d988db6f8ddee46acc7dea6f898510f532ee48f87a0c93"
    hash4       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash5       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash6       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"
    hash7       = "d93efcba4ba3ef570f21adda2cc5413ab9ed3865a53a97ad1e05113ebc7c4787"
    hash8       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"
    hash9       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return" ascii
    $s2 = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(functio" ascii
    $s3 = "eturn \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})()" ascii
    $s4 = "ck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe" ascii
    $s5 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}