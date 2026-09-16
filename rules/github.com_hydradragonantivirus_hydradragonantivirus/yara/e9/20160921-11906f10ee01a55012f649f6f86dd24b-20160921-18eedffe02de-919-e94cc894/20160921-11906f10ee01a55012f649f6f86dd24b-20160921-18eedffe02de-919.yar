rule _20160921_11906f10ee01a55012f649f6f86dd24b_20160921_18eedffe02de_919 {
  meta:
    description = "datamaliciousorder - from files 20160921_11906f10ee01a55012f649f6f86dd24b.js, 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_3a10cf80628434d9e46f20272ebff11d.js, 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_3e1e1d6341df1caf923e4b9f79ea9ac3.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_4d79e96b422e6679059a17d9524e032c.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_694d4629e99fd1d23d60bc73e0e28e30.js, 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js, 20160921_82c6439487239a08e403c18f347e12e6.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js, 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js, 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_cbf1d4fc4e95f977458908fce0f55adb.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"
    hash2       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash3       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash4       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash5       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"
    hash6       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash7       = "d858d56d343b97488263af92c96b6bee8f8213dd2aec4d79132b57f04ea3c568"
    hash8       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash9       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash10      = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"
    hash11      = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash12      = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"
    hash13      = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash14      = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"
    hash15      = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"
    hash16      = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"
    hash17      = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"
    hash18      = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash19      = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"
    hash20      = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"
    hash21      = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash22      = "de5ba60f48e78004cd5ec7a5ae764a46be1381f19aa87a961c3937fd05a1e2ec"
    hash23      = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"
    hash24      = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"
    hash25      = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1  = "n \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Wo0\";})(),(fu" ascii
    $s2  = ";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fuck" ascii
    $s3  = "urn \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(fu" ascii
    $s4  = " fuck(){return \"CCb\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"I" ascii
    $s5  = "ion fuck(){return \"ZVi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return" ascii
    $s6  = "nction fuck(){return \"Qh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s7  = "h\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s8  = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Na\";})(),(function fuck" ascii
    $s9  = "(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s10 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(" ascii
    $s11 = "k(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";}" ascii
    $s12 = "})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Pc\";})(),(function fuc" ascii
    $s13 = "),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s14 = "r\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function" ascii
    $s15 = ",(function fuck(){return \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){r" ascii
    $s16 = "ck(){return \"Jo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\"" ascii
    $s17 = "),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){" ascii
    $s18 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(" ascii
    $s19 = "ck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xw\";}" ascii
    $s20 = "IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}