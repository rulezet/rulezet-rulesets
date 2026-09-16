rule TTP_XOR_QUAD_CurrentVersionRun_df4a {
  strings:
    $key_df4a = { 8c 25 [2] a8 2b [2] 83 07 [2] ad 25 [2] b9 3e [2] b6 24 [2] a8 39 [2] aa 38 [2] b1 3e [2] ad 39 [2] b1 16 }

  condition:
    any of them
}