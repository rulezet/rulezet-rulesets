rule TTP_XOR_QUAD_CurrentVersionRun_7b59 {
  strings:
    $key_7b59 = { 28 36 [2] 0c 38 [2] 27 14 [2] 09 36 [2] 1d 2d [2] 12 37 [2] 0c 2a [2] 0e 2b [2] 15 2d [2] 09 2a [2] 15 05 }

  condition:
    any of them
}