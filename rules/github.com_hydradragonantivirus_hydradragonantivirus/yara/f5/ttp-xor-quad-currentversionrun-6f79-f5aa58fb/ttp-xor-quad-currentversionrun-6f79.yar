rule TTP_XOR_QUAD_CurrentVersionRun_6f79 {
  strings:
    $key_6f79 = { 3c 16 [2] 18 18 [2] 33 34 [2] 1d 16 [2] 09 0d [2] 06 17 [2] 18 0a [2] 1a 0b [2] 01 0d [2] 1d 0a [2] 01 25 }

  condition:
    any of them
}