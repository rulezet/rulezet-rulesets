rule TTP_XOR_QUAD_CurrentVersionRun_712b {
  strings:
    $key_712b = { 22 44 [2] 06 4a [2] 2d 66 [2] 03 44 [2] 17 5f [2] 18 45 [2] 06 58 [2] 04 59 [2] 1f 5f [2] 03 58 [2] 1f 77 }

  condition:
    any of them
}