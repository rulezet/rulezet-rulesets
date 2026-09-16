rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_4031e49cbb76_4657 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_4031e49cbb76e44dd58fa572b63a00c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"

  strings:
    $s1 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s2 = ",(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"TTs\";})(),(function fuck()" ascii
    $s3 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Sx\";})(),(funct" ascii
    $s4 = "uck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IP" ascii
    $s5 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}