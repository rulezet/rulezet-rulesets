rule _20160921_56d2e5a83b597694b265cf7813cc5cf0_20160921_5f5611940db7_3799 {
  meta:
    description = "datamaliciousorder - from files 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_6d9213179dbb863530a638df47003a46.js, 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash2       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash3       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"
    hash4       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash5       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"

  strings:
    $s1 = "(){return \"UEg\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";}" ascii
    $s2 = "ion f000(){return \"MJq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s3 = "){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})" ascii
    $s4 = "m\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s5 = "0(){return \"Sq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s6 = "n f000(){return \"ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"W" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}