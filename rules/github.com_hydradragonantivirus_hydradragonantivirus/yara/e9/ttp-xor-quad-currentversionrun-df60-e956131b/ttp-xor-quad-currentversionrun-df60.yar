rule TTP_XOR_QUAD_CurrentVersionRun_df60 {
  strings:
    $key_df60 = { 8c 0f [2] a8 01 [2] 83 2d [2] ad 0f [2] b9 14 [2] b6 0e [2] a8 13 [2] aa 12 [2] b1 14 [2] ad 13 [2] b1 3c }

  condition:
    any of them
}