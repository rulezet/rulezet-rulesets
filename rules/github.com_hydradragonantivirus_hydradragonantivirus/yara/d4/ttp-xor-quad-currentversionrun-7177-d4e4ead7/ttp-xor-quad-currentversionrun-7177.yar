rule TTP_XOR_QUAD_CurrentVersionRun_7177 {
  strings:
    $key_7177 = { 22 18 [2] 06 16 [2] 2d 3a [2] 03 18 [2] 17 03 [2] 18 19 [2] 06 04 [2] 04 05 [2] 1f 03 [2] 03 04 [2] 1f 2b }

  condition:
    any of them
}