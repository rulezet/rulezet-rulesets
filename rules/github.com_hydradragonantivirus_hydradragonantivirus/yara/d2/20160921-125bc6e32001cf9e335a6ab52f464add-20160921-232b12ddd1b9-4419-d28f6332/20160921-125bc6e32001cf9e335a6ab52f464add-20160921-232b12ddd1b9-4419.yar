rule _20160921_125bc6e32001cf9e335a6ab52f464add_20160921_232b12ddd1b9_4419 {
  meta:
    description = "datamaliciousorder - from files 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash2       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash3       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"
    hash4       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = ")(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function fuck(" ascii
    $s2 = "ction fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return " ascii
    $s3 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function" ascii
    $s4 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Jh\";})(" ascii
    $s5 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}