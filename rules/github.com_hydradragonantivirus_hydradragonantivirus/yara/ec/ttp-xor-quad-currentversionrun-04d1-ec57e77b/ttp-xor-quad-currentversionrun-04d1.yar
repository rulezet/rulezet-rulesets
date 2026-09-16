rule TTP_XOR_QUAD_CurrentVersionRun_04d1 {
  strings:
    $key_04d1 = { 57 be [2] 73 b0 [2] 58 9c [2] 76 be [2] 62 a5 [2] 6d bf [2] 73 a2 [2] 71 a3 [2] 6a a5 [2] 76 a2 [2] 6a 8d }

  condition:
    any of them
}