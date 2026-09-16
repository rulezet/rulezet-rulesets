rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_058ddf4d10ac_3228 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js, 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash3       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash4       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash5       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash6       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash7       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"
    hash8       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash9       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"
    hash10      = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"
    hash11      = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"
    hash12      = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"
    hash13      = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"
    hash14      = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1 = "Pu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s2 = "){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"We\";})" ascii
    $s3 = "SUi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(funct" ascii
    $s4 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s5 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){re" ascii
    $s6 = "tion fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}