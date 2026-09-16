rule TTP_XOR_QUAD_CurrentVersionRun_7348 {
  strings:
    $key_7348 = { 20 27 [2] 04 29 [2] 2f 05 [2] 01 27 [2] 15 3c [2] 1a 26 [2] 04 3b [2] 06 3a [2] 1d 3c [2] 01 3b [2] 1d 14 }

  condition:
    any of them
}