rule TTP_XOR_QUAD_CurrentVersionRun_0f46 {
  strings:
    $key_0f46 = { 5c 29 [2] 78 27 [2] 53 0b [2] 7d 29 [2] 69 32 [2] 66 28 [2] 78 35 [2] 7a 34 [2] 61 32 [2] 7d 35 [2] 61 1a }

  condition:
    any of them
}