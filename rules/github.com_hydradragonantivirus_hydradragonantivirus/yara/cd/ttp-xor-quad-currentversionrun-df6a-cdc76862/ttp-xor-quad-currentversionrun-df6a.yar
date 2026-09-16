rule TTP_XOR_QUAD_CurrentVersionRun_df6a {
  strings:
    $key_df6a = { 8c 05 [2] a8 0b [2] 83 27 [2] ad 05 [2] b9 1e [2] b6 04 [2] a8 19 [2] aa 18 [2] b1 1e [2] ad 19 [2] b1 36 }

  condition:
    any of them
}