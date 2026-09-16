rule _20160921_5e30fe0c691277f3c6d0814d796ba918_20160921_6f8e01604e95_3821 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e30fe0c691277f3c6d0814d796ba918.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js, 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"
    hash2       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"
    hash3       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"

  strings:
    $s1 = "{return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";}" ascii
    $s2 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s3 = "y\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(functio" ascii
    $s4 = "\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function" ascii
    $s5 = "urn \"IRn\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(" ascii
    $s6 = "){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}