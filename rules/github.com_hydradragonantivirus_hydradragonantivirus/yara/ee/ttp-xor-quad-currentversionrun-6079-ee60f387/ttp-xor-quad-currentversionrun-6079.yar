rule TTP_XOR_QUAD_CurrentVersionRun_6079 {
  strings:
    $key_6079 = { 33 16 [2] 17 18 [2] 3c 34 [2] 12 16 [2] 06 0d [2] 09 17 [2] 17 0a [2] 15 0b [2] 0e 0d [2] 12 0a [2] 0e 25 }

  condition:
    any of them
}