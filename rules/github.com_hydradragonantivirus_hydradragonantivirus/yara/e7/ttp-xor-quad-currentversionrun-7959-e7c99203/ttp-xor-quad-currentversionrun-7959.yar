rule TTP_XOR_QUAD_CurrentVersionRun_7959 {
  strings:
    $key_7959 = { 2a 36 [2] 0e 38 [2] 25 14 [2] 0b 36 [2] 1f 2d [2] 10 37 [2] 0e 2a [2] 0c 2b [2] 17 2d [2] 0b 2a [2] 17 05 }

  condition:
    any of them
}