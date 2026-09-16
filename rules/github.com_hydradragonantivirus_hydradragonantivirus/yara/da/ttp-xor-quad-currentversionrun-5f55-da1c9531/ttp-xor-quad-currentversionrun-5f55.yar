rule TTP_XOR_QUAD_CurrentVersionRun_5f55 {
  strings:
    $key_5f55 = { 0c 3a [2] 28 34 [2] 03 18 [2] 2d 3a [2] 39 21 [2] 36 3b [2] 28 26 [2] 2a 27 [2] 31 21 [2] 2d 26 [2] 31 09 }

  condition:
    any of them
}