rule TTP_XOR_QUAD_CurrentVersionRun_60f4 {
  strings:
    $key_60f4 = { 33 9b [2] 17 95 [2] 3c b9 [2] 12 9b [2] 06 80 [2] 09 9a [2] 17 87 [2] 15 86 [2] 0e 80 [2] 12 87 [2] 0e a8 }

  condition:
    any of them
}