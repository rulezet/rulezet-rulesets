rule TTP_XOR_QUAD_CurrentVersionRun_0146 {
  strings:
    $key_0146 = { 52 29 [2] 76 27 [2] 5d 0b [2] 73 29 [2] 67 32 [2] 68 28 [2] 76 35 [2] 74 34 [2] 6f 32 [2] 73 35 [2] 6f 1a }

  condition:
    any of them
}