rule TTP_XOR_QUAD_CurrentVersionRun_5f54 {
  strings:
    $key_5f54 = { 0c 3b [2] 28 35 [2] 03 19 [2] 2d 3b [2] 39 20 [2] 36 3a [2] 28 27 [2] 2a 26 [2] 31 20 [2] 2d 27 [2] 31 08 }

  condition:
    any of them
}