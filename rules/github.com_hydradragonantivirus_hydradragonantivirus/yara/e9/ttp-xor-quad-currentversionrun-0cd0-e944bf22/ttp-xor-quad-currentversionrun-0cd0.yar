rule TTP_XOR_QUAD_CurrentVersionRun_0cd0 {
  strings:
    $key_0cd0 = { 5f bf [2] 7b b1 [2] 50 9d [2] 7e bf [2] 6a a4 [2] 65 be [2] 7b a3 [2] 79 a2 [2] 62 a4 [2] 7e a3 [2] 62 8c }

  condition:
    any of them
}