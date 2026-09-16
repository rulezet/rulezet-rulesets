rule TTP_XOR_QUAD_CurrentVersionRun_2259 {
  strings:
    $key_2259 = { 71 36 [2] 55 38 [2] 7e 14 [2] 50 36 [2] 44 2d [2] 4b 37 [2] 55 2a [2] 57 2b [2] 4c 2d [2] 50 2a [2] 4c 05 }

  condition:
    any of them
}