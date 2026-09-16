rule TTP_XOR_QUAD_CurrentVersionRun_1eca {
  strings:
    $key_1eca = { 4d a5 [2] 69 ab [2] 42 87 [2] 6c a5 [2] 78 be [2] 77 a4 [2] 69 b9 [2] 6b b8 [2] 70 be [2] 6c b9 [2] 70 96 }

  condition:
    any of them
}