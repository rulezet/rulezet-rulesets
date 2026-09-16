rule TTP_XOR_QUAD_CurrentVersionRun_6059 {
  strings:
    $key_6059 = { 33 36 [2] 17 38 [2] 3c 14 [2] 12 36 [2] 06 2d [2] 09 37 [2] 17 2a [2] 15 2b [2] 0e 2d [2] 12 2a [2] 0e 05 }

  condition:
    any of them
}