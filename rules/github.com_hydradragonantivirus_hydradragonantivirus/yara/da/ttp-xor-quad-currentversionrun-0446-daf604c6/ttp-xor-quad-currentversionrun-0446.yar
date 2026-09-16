rule TTP_XOR_QUAD_CurrentVersionRun_0446 {
  strings:
    $key_0446 = { 57 29 [2] 73 27 [2] 58 0b [2] 76 29 [2] 62 32 [2] 6d 28 [2] 73 35 [2] 71 34 [2] 6a 32 [2] 76 35 [2] 6a 1a }

  condition:
    any of them
}