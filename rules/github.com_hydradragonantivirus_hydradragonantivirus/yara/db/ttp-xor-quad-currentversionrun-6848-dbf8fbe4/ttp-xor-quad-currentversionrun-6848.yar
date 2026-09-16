rule TTP_XOR_QUAD_CurrentVersionRun_6848 {
  strings:
    $key_6848 = { 3b 27 [2] 1f 29 [2] 34 05 [2] 1a 27 [2] 0e 3c [2] 01 26 [2] 1f 3b [2] 1d 3a [2] 06 3c [2] 1a 3b [2] 06 14 }

  condition:
    any of them
}