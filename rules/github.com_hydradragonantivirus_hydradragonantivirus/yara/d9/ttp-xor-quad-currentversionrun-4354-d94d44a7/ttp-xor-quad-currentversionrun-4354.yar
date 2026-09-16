rule TTP_XOR_QUAD_CurrentVersionRun_4354 {
  strings:
    $key_4354 = { 10 3b [2] 34 35 [2] 1f 19 [2] 31 3b [2] 25 20 [2] 2a 3a [2] 34 27 [2] 36 26 [2] 2d 20 [2] 31 27 [2] 2d 08 }

  condition:
    any of them
}