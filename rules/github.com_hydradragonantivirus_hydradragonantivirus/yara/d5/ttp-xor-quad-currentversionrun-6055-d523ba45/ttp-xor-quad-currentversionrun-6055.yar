rule TTP_XOR_QUAD_CurrentVersionRun_6055 {
  strings:
    $key_6055 = { 33 3a [2] 17 34 [2] 3c 18 [2] 12 3a [2] 06 21 [2] 09 3b [2] 17 26 [2] 15 27 [2] 0e 21 [2] 12 26 [2] 0e 09 }

  condition:
    any of them
}