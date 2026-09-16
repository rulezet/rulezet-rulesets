rule TTP_XOR_QUAD_CurrentVersionRun_6859 {
  strings:
    $key_6859 = { 3b 36 [2] 1f 38 [2] 34 14 [2] 1a 36 [2] 0e 2d [2] 01 37 [2] 1f 2a [2] 1d 2b [2] 06 2d [2] 1a 2a [2] 06 05 }

  condition:
    any of them
}