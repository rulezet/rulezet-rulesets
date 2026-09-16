rule TTP_XOR_QUAD_CurrentVersionRun_5a04 {
  strings:
    $key_5a04 = { 09 6b [2] 2d 65 [2] 06 49 [2] 28 6b [2] 3c 70 [2] 33 6a [2] 2d 77 [2] 2f 76 [2] 34 70 [2] 28 77 [2] 34 58 }

  condition:
    any of them
}