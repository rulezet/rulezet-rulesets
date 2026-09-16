rule TTP_XOR_QUAD_CurrentVersionRun_2559 {
  strings:
    $key_2559 = { 76 36 [2] 52 38 [2] 79 14 [2] 57 36 [2] 43 2d [2] 4c 37 [2] 52 2a [2] 50 2b [2] 4b 2d [2] 57 2a [2] 4b 05 }

  condition:
    any of them
}