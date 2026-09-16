rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_1363f95b1c66_4213 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_5230866e44eda4e054d929933fdfdae1.js, 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js, 20160921_70b567ca258b3c505e14f3c712366f09.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash3       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"
    hash4       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"
    hash5       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"
    hash6       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash7       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"
    hash8       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"
    hash9       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1 = "Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"LLv\";})(),(function" ascii
    $s2 = "{return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})()" ascii
    $s3 = "on fuck(){return \"Ar\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"" ascii
    $s4 = "function fuck(){return \"Wo\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s5 = ",(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"To\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}