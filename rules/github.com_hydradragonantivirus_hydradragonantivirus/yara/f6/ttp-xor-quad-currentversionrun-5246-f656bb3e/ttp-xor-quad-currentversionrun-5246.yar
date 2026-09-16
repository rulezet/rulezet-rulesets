rule TTP_XOR_QUAD_CurrentVersionRun_5246 {
  strings:
    $key_5246 = { 01 29 [2] 25 27 [2] 0e 0b [2] 20 29 [2] 34 32 [2] 3b 28 [2] 25 35 [2] 27 34 [2] 3c 32 [2] 20 35 [2] 3c 1a }

  condition:
    any of them
}