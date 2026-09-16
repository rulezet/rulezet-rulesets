rule TTP_XOR_QUAD_CurrentVersionRun_2f46 {
  strings:
    $key_2f46 = { 7c 29 [2] 58 27 [2] 73 0b [2] 5d 29 [2] 49 32 [2] 46 28 [2] 58 35 [2] 5a 34 [2] 41 32 [2] 5d 35 [2] 41 1a }

  condition:
    any of them
}