rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_1bb9bdcf05b8_856 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_460a913db46b41c41035cc210ed5fba0.js, 20160921_50b14bf13c50bc31f09e3c583e1d422d.js, 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_6d7b654a484acab4abb3060ebc68a164.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js, 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_82861e992460412d02ca3f987da7d467.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js, 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js, 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash3       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash4       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash5       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash6       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash7       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"
    hash8       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"
    hash9       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash10      = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash11      = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"
    hash12      = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"
    hash13      = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash14      = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash15      = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash16      = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"
    hash17      = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash18      = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"
    hash19      = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"
    hash20      = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash21      = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"
    hash22      = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"
    hash23      = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"
    hash24      = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"
    hash25      = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1  = "tion fuck(){return \"DWe\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s2  = "){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Mw\";})(" ascii
    $s3  = "uck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\"" ascii
    $s4  = ",(function fuck(){return \"Nm\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){r" ascii
    $s5  = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ai\";})(),(function" ascii
    $s6  = "on fuck(){return \"Nm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"" ascii
    $s7  = "Jx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s8  = "n fuck(){return \"ZLd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s9  = "nction fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){retur" ascii
    $s10 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ar\";})(),(function fuc" ascii
    $s11 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){" ascii
    $s12 = "(){return \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})" ascii
    $s13 = "\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xw\";})(),(function f" ascii
    $s14 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){re" ascii
    $s15 = "ck(){return \"Ve\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Vb\";}" ascii
    $s16 = "n \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Za\";})(),(fun" ascii
    $s17 = "Yk\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s18 = " fuck(){return \"Wo\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s19 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Wo0\";})(),(func" ascii
    $s20 = "return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Mw\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}