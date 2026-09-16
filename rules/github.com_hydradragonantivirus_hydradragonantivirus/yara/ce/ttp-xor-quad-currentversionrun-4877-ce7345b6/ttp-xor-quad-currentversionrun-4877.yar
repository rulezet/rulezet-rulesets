rule TTP_XOR_QUAD_CurrentVersionRun_4877 {
  strings:
    $key_4877 = { 1b 18 [2] 3f 16 [2] 14 3a [2] 3a 18 [2] 2e 03 [2] 21 19 [2] 3f 04 [2] 3d 05 [2] 26 03 [2] 3a 04 [2] 26 2b }

  condition:
    any of them
}