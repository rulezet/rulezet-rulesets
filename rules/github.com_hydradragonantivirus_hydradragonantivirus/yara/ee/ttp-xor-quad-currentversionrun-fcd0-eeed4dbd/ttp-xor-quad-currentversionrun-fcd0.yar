rule TTP_XOR_QUAD_CurrentVersionRun_fcd0 {
  strings:
    $key_fcd0 = { af bf [2] 8b b1 [2] a0 9d [2] 8e bf [2] 9a a4 [2] 95 be [2] 8b a3 [2] 89 a2 [2] 92 a4 [2] 8e a3 [2] 92 8c }

  condition:
    any of them
}