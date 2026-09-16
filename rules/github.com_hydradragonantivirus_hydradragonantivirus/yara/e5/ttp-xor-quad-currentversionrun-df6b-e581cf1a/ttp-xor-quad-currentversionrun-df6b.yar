rule TTP_XOR_QUAD_CurrentVersionRun_df6b {
  strings:
    $key_df6b = { 8c 04 [2] a8 0a [2] 83 26 [2] ad 04 [2] b9 1f [2] b6 05 [2] a8 18 [2] aa 19 [2] b1 1f [2] ad 18 [2] b1 37 }

  condition:
    any of them
}