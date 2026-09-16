rule TTP_XOR_QUAD_CurrentVersionRun_1177 {
  strings:
    $key_1177 = { 42 18 [2] 66 16 [2] 4d 3a [2] 63 18 [2] 77 03 [2] 78 19 [2] 66 04 [2] 64 05 [2] 7f 03 [2] 63 04 [2] 7f 2b }

  condition:
    any of them
}