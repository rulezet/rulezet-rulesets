rule _20160921_939d60f07d4171a5bae4c0b4ca33f3d9_20160921_cae1392fd0c6_5556 {
  meta:
    description = "datamaliciousorder - from files 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"
    hash2       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash3       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1 = " \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq\";})(),(func" ascii
    $s2 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sj" ascii
    $s3 = "(){return \"KZr\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Oe\";}" ascii
    $s4 = " \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Tn\";})(),(func" ascii
    $s5 = "eturn \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}