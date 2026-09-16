rule TTP_XOR_QUAD_CurrentVersionRun_df56 {
  strings:
    $key_df56 = { 8c 39 [2] a8 37 [2] 83 1b [2] ad 39 [2] b9 22 [2] b6 38 [2] a8 25 [2] aa 24 [2] b1 22 [2] ad 25 [2] b1 0a }

  condition:
    any of them
}