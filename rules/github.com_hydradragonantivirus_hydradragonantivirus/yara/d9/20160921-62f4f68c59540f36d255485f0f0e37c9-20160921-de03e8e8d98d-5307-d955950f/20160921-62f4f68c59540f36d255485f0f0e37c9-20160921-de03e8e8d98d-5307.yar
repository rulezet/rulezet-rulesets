rule _20160921_62f4f68c59540f36d255485f0f0e37c9_20160921_de03e8e8d98d_5307 {
  meta:
    description = "datamaliciousorder - from files 20160921_62f4f68c59540f36d255485f0f0e37c9.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js, 20160921_ee6d5c7dc2c03b89ea5ef53aa0c676a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"
    hash2       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"
    hash3       = "ddd3db3929119812b70ad9f62bd3187b6108d24999c41a8ff5390bc9a60387a3"

  strings:
    $s1 = "n \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s2 = "ck(){return \"Pc\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";}" ascii
    $s3 = ";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"CCb\";})(),(function fu" ascii
    $s4 = "ction fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){retur" ascii
    $s5 = "ck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}