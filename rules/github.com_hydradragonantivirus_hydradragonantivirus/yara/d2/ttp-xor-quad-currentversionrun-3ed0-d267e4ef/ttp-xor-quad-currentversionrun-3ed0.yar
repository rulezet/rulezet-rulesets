rule TTP_XOR_QUAD_CurrentVersionRun_3ed0 {
  strings:
    $key_3ed0 = { 6d bf [2] 49 b1 [2] 62 9d [2] 4c bf [2] 58 a4 [2] 57 be [2] 49 a3 [2] 4b a2 [2] 50 a4 [2] 4c a3 [2] 50 8c }

  condition:
    any of them
}