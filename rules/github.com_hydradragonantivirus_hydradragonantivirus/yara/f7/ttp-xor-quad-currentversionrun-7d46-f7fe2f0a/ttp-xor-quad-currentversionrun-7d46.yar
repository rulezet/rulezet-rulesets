rule TTP_XOR_QUAD_CurrentVersionRun_7d46 {
  strings:
    $key_7d46 = { 2e 29 [2] 0a 27 [2] 21 0b [2] 0f 29 [2] 1b 32 [2] 14 28 [2] 0a 35 [2] 08 34 [2] 13 32 [2] 0f 35 [2] 13 1a }

  condition:
    any of them
}