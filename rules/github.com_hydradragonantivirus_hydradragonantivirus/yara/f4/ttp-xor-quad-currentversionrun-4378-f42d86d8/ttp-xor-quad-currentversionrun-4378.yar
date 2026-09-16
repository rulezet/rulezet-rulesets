rule TTP_XOR_QUAD_CurrentVersionRun_4378 {
  strings:
    $key_4378 = { 10 17 [2] 34 19 [2] 1f 35 [2] 31 17 [2] 25 0c [2] 2a 16 [2] 34 0b [2] 36 0a [2] 2d 0c [2] 31 0b [2] 2d 24 }

  condition:
    any of them
}