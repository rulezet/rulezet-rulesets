rule TTP_XOR_QUAD_CurrentVersionRun_4444 {
  strings:
    $key_4444 = { 17 2b [2] 33 25 [2] 18 09 [2] 36 2b [2] 22 30 [2] 2d 2a [2] 33 37 [2] 31 36 [2] 2a 30 [2] 36 37 [2] 2a 18 }

  condition:
    any of them
}