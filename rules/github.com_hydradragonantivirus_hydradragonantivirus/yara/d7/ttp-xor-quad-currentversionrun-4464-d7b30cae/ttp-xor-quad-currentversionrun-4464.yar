rule TTP_XOR_QUAD_CurrentVersionRun_4464 {
  strings:
    $key_4464 = { 17 0b [2] 33 05 [2] 18 29 [2] 36 0b [2] 22 10 [2] 2d 0a [2] 33 17 [2] 31 16 [2] 2a 10 [2] 36 17 [2] 2a 38 }

  condition:
    any of them
}