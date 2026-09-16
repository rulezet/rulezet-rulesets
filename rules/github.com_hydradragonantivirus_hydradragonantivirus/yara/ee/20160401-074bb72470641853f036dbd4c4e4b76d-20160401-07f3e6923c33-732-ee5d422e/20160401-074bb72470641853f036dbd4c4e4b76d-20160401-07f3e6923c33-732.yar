rule _20160401_074bb72470641853f036dbd4c4e4b76d_20160401_07f3e6923c33_732 {
  meta:
    description = "datamaliciousorder - from files 20160401_074bb72470641853f036dbd4c4e4b76d.js, 20160401_07f3e6923c331e9fa2ac0064035660cd.js, 20160401_13604d0b3f04730f5705dc718573b24a.js, 20160401_19bf40a5a991edb5577279eb5c8dbb80.js, 20160401_21ec5b06578233efc7097545d1b8eaa0.js, 20160401_3a0fb3defa4cbb21471551d159770593.js, 20160401_4d24b26be9e17210b669701c295b1f1b.js, 20160401_55c937ffb608d183fabcfaa675d37643.js, 20160401_61adaf25f2c41debaf9cf91b623eabaf.js, 20160401_6556537d8b8fc3b0d0a28ff734d452da.js, 20160401_69dd042abf1c84ca1068310051559e65.js, 20160401_7a83db5f861741921c65ccc3b785a4fa.js, 20160401_85ee76bc4e31aefe8d6fb467aec3cc35.js, 20160401_91f2669fa34f280fcc71b253f42224b2.js, 20160401_942cfc29fd9be88af0b4490d4668524a.js, 20160401_997b885923183f9ab5bad60506e4d34d.js, 20160401_b10cb843ce08859276830ca2730197ad.js, 20160401_b2bbc6a8204283e944e740c9c6d2ad5e.js, 20160401_b345b6ca5e49fc4908929b034179b628.js, 20160401_c97d496a71397819a0e5b06824fef071.js, 20160401_cfbf98d90d17f5f67c797c15276516b9.js, 20160401_e0b251081e4ad8c69425997a209d9b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67c5286fbd523d1cbcb0e8a292f265f52707bba6ac5940fb87d7dfd790d7f8c7"
    hash2       = "956b2696e81ee44b2a25c248c9a4a38ea9957d5a31716adfdaf0adb5157509b9"
    hash3       = "fc31f55739b58ef7b394b7d81342de67721c00837ef6dd2f7c3c147f6630a95e"
    hash4       = "2947dfe8bbc772895d19b6856c70aedb5222d167ff27376d08341f898f7ca6c2"
    hash5       = "f77e74bc29a6199c983f3150c11f488e6895ca176bcdbb11c7811db6e2380871"
    hash6       = "7fe8f7c3be8e4ed3ac474af471eec48e6aa61bfedf56dc37bca4743b6a8715f5"
    hash7       = "cd2e0d14d78f907423bd9fe377e209a4af55215a2fcaf547a7cc60c085707d53"
    hash8       = "4730b85b1c6557bbe646c3005f2f298802c16f35f6cd38f8a810290d878bd95e"
    hash9       = "ad91c623331700a67a2afd191c183acb05b8653702f5225fa6c44998f39c6bf9"
    hash10      = "f023d39af370560dcb899db7f0060ebbd4db7429efd2dc258f0aae51e29e82ed"
    hash11      = "8503f36df450d9c602b58ee698d6a7c49be4bffa999e1613b64e3fa0b19608fa"
    hash12      = "c55978d1525767066e7afa4ff74f983ce748c75de7474539e19d3d4392e120d7"
    hash13      = "071e5a78ea5c0f33959eb00047e0e0269f9bd6a47b81f5ad2bb613f637d85474"
    hash14      = "5d07c5717d3a38f6ef2797dafa1ba2c715fea5553864fae9b61a0340f544de93"
    hash15      = "fa6f399e6c861d00e0aa1ec7e06a9c4d7f34a1f11b150210d24827d9f2eb145d"
    hash16      = "63c7f984490055a8ca35857d088797cd2c4c4a1f79bd2bcc5ed34adbb8f40157"
    hash17      = "c4b30dd19246791d57ac6b0b2650991ebd95c11f22c77c2443a8cdeaaee129e7"
    hash18      = "618a480b7265483568b7045779cacb2f26f49cb8f9ddd0b0a8de0313654276fd"
    hash19      = "173f9b12426390983da50456b0ec8fecd0ed5ec58d6dfd4cbf54a92463495e9e"
    hash20      = "0b4edeb36749b21d97b60334cfd99355821f37db764990e9767b1419f8009fc8"
    hash21      = "866cc3ba9b91ab60a1b3866b9ba0c1fc1da666ae973cd85a83acd629a75931c8"
    hash22      = "206f7171e26213fc0c899cba6bd080d336b70550a663d9f53ec1cbb463310cc6"

  strings:
    $s1  = "var Kolldq =parentings + (\"scholarship\",\"still\",\"temperatures\",\"warrior\",\"e\") + ((\"interference\", \"fakir\", \"leggi" ascii
    $s2  = "daunt = String[(\"noncommissioned\",\"earrings\",\"gateway\",\"f\")+(\"pistil\",\"damnation\",\"prematurely\",\"ro\")+\"mC\"+\"h" ascii
    $s3  = "        kBbeKmxnB[(anthology + (\"choler\",\"conscripts\",\"o\")+\"Di\"+(\"knitting\",\"tulip\",\"ti\")+\"on\").replace(\"D\", p" ascii
    $s4  = "anthology = ((\"perth\", \"athlete\", \"propulsion\", \"exterior\", \"pvxeaWkCIoe\") + \"iByxNYVWCi\").pennies(0);" fullword ascii
    $s5  = "7 + irritable -1);" fullword ascii
    $s6  = "nal\", \"transvaal\", \"nwHMpLdEi\") + \"AocYoqu\").pennies(forgotten) + ((\"instructor\", \"thesis\", \"seething\", \"wharves\"" ascii
    $s7  = "daunt = String[(\"noncommissioned\",\"earrings\",\"gateway\",\"f\")+(\"pistil\",\"damnation\",\"prematurely\",\"ro\")+\"mC\"+\"h" ascii
    $s8  = "asy\",\"incidence\",\"vatican\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s9  = "\"+\"dE\"+\"nv\"+(\"indisputable\",\"media\",\"humor\",\"iron\")+\"me\"+\"nt\"+\"St\"+\"ri\"+\"ngs\", (\"contraband\",\"sarcopha" ascii
    $s10 = "    disembodied.assignment = disembodied.magnificently[(\"c\"+\"hD\"+\"rA\"+(\"vishnu\",\"havoc\",\"manatarms\",\"t\")).replace(" ascii
    $s11 = "            UKvRCMr[(annie).reverse().join(\"\")]((\"panties\",\"symptoms\",\"acknowledgement\",\"G\") + numerouse + (\"acknowle" ascii

  condition:
    (uint16(0) == 0x424d and (8 of them)
    ) or (all of them)
}