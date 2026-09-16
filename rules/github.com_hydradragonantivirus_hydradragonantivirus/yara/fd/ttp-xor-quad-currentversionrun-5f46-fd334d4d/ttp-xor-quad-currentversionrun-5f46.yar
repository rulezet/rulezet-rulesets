rule TTP_XOR_QUAD_CurrentVersionRun_5f46 {
  strings:
    $key_5f46 = { 0c 29 [2] 28 27 [2] 03 0b [2] 2d 29 [2] 39 32 [2] 36 28 [2] 28 35 [2] 2a 34 [2] 31 32 [2] 2d 35 [2] 31 1a }

  condition:
    any of them
}