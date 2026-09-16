rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_058ddf4d10ac_1322 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js, 20160921_d905978b34bea5948e843dd7ecb9dc6e.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash3       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash4       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash5       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash6       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"
    hash7       = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"
    hash8       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"
    hash9       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"
    hash10      = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"
    hash11      = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1  = "n \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s2  = "\"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(functi" ascii
    $s3  = "){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4  = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){ret" ascii
    $s5  = "){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})" ascii
    $s6  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"KVh" ascii
    $s7  = " fuck(){return \"Xw\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IP" ascii
    $s8  = "return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s9  = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return " ascii
    $s10 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(functi" ascii
    $s11 = "k(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\"" ascii
    $s12 = "fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\"" ascii
    $s13 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return " ascii
    $s14 = " fuck(){return \"Yk\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IP" ascii
    $s15 = "ction fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}