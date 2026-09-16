rule _20160921_3a10cf80628434d9e46f20272ebff11d_20160921_3a789c5184fa_456 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a10cf80628434d9e46f20272ebff11d.js, 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_4d79e96b422e6679059a17d9524e032c.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_694d4629e99fd1d23d60bc73e0e28e30.js, 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js, 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"
    hash2       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash3       = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"
    hash4       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash5       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"
    hash6       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash7       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"
    hash8       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash9       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"

  strings:
    $s1  = "\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xw\";})(),(function fu" ascii
    $s2  = "on fuck(){return \"DWe\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return " ascii
    $s3  = "})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Xw\";})(),(function fuck" ascii
    $s4  = "urn \"Zy\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s5  = "u\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s6  = "turn \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Jg\";})(),(fu" ascii
    $s7  = "k(){return \"MUs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Mw\";" ascii
    $s8  = "uck(){return \"Ot\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"GNm" ascii
    $s9  = "nction fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){retu" ascii
    $s10 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"D" ascii
    $s11 = "ion fuck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return " ascii
    $s12 = "(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s13 = "ction fuck(){return \"We\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s14 = "fuck(){return \"Zy\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu" ascii
    $s15 = "rn \"FJs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s16 = "unction fuck(){return \"Hs\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){ret" ascii
    $s17 = "(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Cd\";}" ascii
    $s18 = "tion fuck(){return \"FJs\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return " ascii
    $s19 = "){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})" ascii
    $s20 = "ck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"GNm" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}