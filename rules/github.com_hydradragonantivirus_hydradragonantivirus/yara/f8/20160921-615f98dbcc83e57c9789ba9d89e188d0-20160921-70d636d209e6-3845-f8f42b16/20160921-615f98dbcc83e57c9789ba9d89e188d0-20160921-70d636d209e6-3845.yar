rule _20160921_615f98dbcc83e57c9789ba9d89e188d0_20160921_70d636d209e6_3845 {
  meta:
    description = "datamaliciousorder - from files 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_70d636d209e6f109a21746567376cc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash2       = "6e26044e7a07a5a675f3b388e6309b138b9e7a1aa61556485f444025164a158e"

  strings:
    $s1 = "OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(funct" ascii
    $s2 = "Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function" ascii
    $s3 = "ck(){return \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh" ascii
    $s4 = "(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){" ascii
    $s5 = "k(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s6 = "\"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}