rule TTP_XOR_QUAD_CurrentVersionRun_5273 {
  strings:
    $key_5273 = { 01 1c [2] 25 12 [2] 0e 3e [2] 20 1c [2] 34 07 [2] 3b 1d [2] 25 00 [2] 27 01 [2] 3c 07 [2] 20 00 [2] 3c 2f }

  condition:
    any of them
}