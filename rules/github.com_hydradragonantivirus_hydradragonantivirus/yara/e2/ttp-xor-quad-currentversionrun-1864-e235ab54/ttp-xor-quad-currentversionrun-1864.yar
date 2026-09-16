rule TTP_XOR_QUAD_CurrentVersionRun_1864 {
  strings:
    $key_1864 = { 4b 0b [2] 6f 05 [2] 44 29 [2] 6a 0b [2] 7e 10 [2] 71 0a [2] 6f 17 [2] 6d 16 [2] 76 10 [2] 6a 17 [2] 76 38 }

  condition:
    any of them
}