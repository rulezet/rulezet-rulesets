rule TTP_XOR_QUAD_CurrentVersionRun_5a55 {
  strings:
    $key_5a55 = { 09 3a [2] 2d 34 [2] 06 18 [2] 28 3a [2] 3c 21 [2] 33 3b [2] 2d 26 [2] 2f 27 [2] 34 21 [2] 28 26 [2] 34 09 }

  condition:
    any of them
}