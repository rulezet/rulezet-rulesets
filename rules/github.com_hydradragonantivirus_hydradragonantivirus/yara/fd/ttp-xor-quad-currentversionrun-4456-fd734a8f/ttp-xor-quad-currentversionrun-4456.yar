rule TTP_XOR_QUAD_CurrentVersionRun_4456 {
  strings:
    $key_4456 = { 17 39 [2] 33 37 [2] 18 1b [2] 36 39 [2] 22 22 [2] 2d 38 [2] 33 25 [2] 31 24 [2] 2a 22 [2] 36 25 [2] 2a 0a }

  condition:
    any of them
}