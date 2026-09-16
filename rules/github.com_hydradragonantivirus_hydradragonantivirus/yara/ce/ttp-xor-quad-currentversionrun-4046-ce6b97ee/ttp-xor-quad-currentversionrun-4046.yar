rule TTP_XOR_QUAD_CurrentVersionRun_4046 {
  strings:
    $key_4046 = { 13 29 [2] 37 27 [2] 1c 0b [2] 32 29 [2] 26 32 [2] 29 28 [2] 37 35 [2] 35 34 [2] 2e 32 [2] 32 35 [2] 2e 1a }

  condition:
    any of them
}