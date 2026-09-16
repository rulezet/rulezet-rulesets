rule TTP_XOR_QUAD_CurrentVersionRun_4455 {
  strings:
    $key_4455 = { 17 3a [2] 33 34 [2] 18 18 [2] 36 3a [2] 22 21 [2] 2d 3b [2] 33 26 [2] 31 27 [2] 2a 21 [2] 36 26 [2] 2a 09 }

  condition:
    any of them
}