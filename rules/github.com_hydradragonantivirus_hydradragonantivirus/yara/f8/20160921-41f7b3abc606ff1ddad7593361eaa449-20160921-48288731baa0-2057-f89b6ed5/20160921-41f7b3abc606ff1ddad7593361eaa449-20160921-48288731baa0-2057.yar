rule _20160921_41f7b3abc606ff1ddad7593361eaa449_20160921_48288731baa0_2057 {
  meta:
    description = "datamaliciousorder - from files 20160921_41f7b3abc606ff1ddad7593361eaa449.js, 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_5d253f3fb31881c7c27141d74e02cacb.js, 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_e24d9e7aa16c031b748aba6965b02dcb.js, 20160921_e71c0801261b54c695ea1dac03e838bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e06a7234c6522ba26a61e46d13312e1063594b0e33bec9fae49d2dc4b77c28"
    hash2       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash3       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash4       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"
    hash5       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash6       = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"
    hash7       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash8       = "c005836c702d4e1615fb302fc6f799ca097db41daa5b8cf6a66e8874a454d65b"
    hash9       = "c36b557af1bcfc43e39bfaabcd74048c39fc37b5ac0e9561b161a6d3d2e54e76"

  strings:
    $s1 = "(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"EHo\";})" ascii
    $s2 = "{return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s3 = "k(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Vb\"" ascii
    $s4 = "),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){r" ascii
    $s5 = "\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function " ascii
    $s6 = "return \"Xg\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(" ascii
    $s7 = "tion fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){retur" ascii
    $s8 = "\"XCr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(funct" ascii
    $s9 = "n fuck(){return \"LLv\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"X" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}