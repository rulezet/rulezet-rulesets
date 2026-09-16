rule TTP_XOR_QUAD_CurrentVersionRun_6054 {
  strings:
    $key_6054 = { 33 3b [2] 17 35 [2] 3c 19 [2] 12 3b [2] 06 20 [2] 09 3a [2] 17 27 [2] 15 26 [2] 0e 20 [2] 12 27 [2] 0e 08 }

  condition:
    any of them
}