rule TTP_XOR_QUAD_CurrentVersionRun_df40 {
  strings:
    $key_df40 = { 8c 2f [2] a8 21 [2] 83 0d [2] ad 2f [2] b9 34 [2] b6 2e [2] a8 33 [2] aa 32 [2] b1 34 [2] ad 33 [2] b1 1c }

  condition:
    any of them
}