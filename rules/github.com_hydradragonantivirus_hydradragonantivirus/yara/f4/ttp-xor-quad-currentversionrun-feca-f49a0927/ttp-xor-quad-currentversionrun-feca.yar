rule TTP_XOR_QUAD_CurrentVersionRun_feca {
  strings:
    $key_feca = { ad a5 [2] 89 ab [2] a2 87 [2] 8c a5 [2] 98 be [2] 97 a4 [2] 89 b9 [2] 8b b8 [2] 90 be [2] 8c b9 [2] 90 96 }

  condition:
    any of them
}