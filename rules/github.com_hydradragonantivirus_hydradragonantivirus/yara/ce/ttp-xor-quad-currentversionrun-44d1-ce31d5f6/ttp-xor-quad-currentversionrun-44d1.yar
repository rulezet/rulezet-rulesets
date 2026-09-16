rule TTP_XOR_QUAD_CurrentVersionRun_44d1 {
  strings:
    $key_44d1 = { 17 be [2] 33 b0 [2] 18 9c [2] 36 be [2] 22 a5 [2] 2d bf [2] 33 a2 [2] 31 a3 [2] 2a a5 [2] 36 a2 [2] 2a 8d }

  condition:
    any of them
}