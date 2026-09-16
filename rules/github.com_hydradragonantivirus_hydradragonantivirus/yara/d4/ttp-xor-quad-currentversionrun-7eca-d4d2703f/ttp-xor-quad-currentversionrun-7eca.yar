rule TTP_XOR_QUAD_CurrentVersionRun_7eca {
  strings:
    $key_7eca = { 2d a5 [2] 09 ab [2] 22 87 [2] 0c a5 [2] 18 be [2] 17 a4 [2] 09 b9 [2] 0b b8 [2] 10 be [2] 0c b9 [2] 10 96 }

  condition:
    any of them
}