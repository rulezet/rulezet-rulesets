rule TTP_XOR_QUAD_CurrentVersionRun_60f8 {
  strings:
    $key_60f8 = { 33 97 [2] 17 99 [2] 3c b5 [2] 12 97 [2] 06 8c [2] 09 96 [2] 17 8b [2] 15 8a [2] 0e 8c [2] 12 8b [2] 0e a4 }

  condition:
    any of them
}