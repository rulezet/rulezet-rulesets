rule TTP_XOR_QUAD_CurrentVersionRun_1846 {
  strings:
    $key_1846 = { 4b 29 [2] 6f 27 [2] 44 0b [2] 6a 29 [2] 7e 32 [2] 71 28 [2] 6f 35 [2] 6d 34 [2] 76 32 [2] 6a 35 [2] 76 1a }

  condition:
    any of them
}