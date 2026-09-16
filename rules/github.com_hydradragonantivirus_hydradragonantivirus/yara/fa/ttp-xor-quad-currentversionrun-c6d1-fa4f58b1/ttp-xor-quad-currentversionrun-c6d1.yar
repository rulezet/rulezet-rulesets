rule TTP_XOR_QUAD_CurrentVersionRun_c6d1 {
  strings:
    $key_c6d1 = { 95 be [2] b1 b0 [2] 9a 9c [2] b4 be [2] a0 a5 [2] af bf [2] b1 a2 [2] b3 a3 [2] a8 a5 [2] b4 a2 [2] a8 8d }

  condition:
    any of them
}