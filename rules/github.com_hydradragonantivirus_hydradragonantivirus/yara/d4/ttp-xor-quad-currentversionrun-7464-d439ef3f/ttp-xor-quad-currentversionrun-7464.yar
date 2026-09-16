rule TTP_XOR_QUAD_CurrentVersionRun_7464 {
  strings:
    $key_7464 = { 27 0b [2] 03 05 [2] 28 29 [2] 06 0b [2] 12 10 [2] 1d 0a [2] 03 17 [2] 01 16 [2] 1a 10 [2] 06 17 [2] 1a 38 }

  condition:
    any of them
}