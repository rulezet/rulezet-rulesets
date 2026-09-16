rule TTP_XOR_QUAD_CurrentVersionRun_df7b {
  strings:
    $key_df7b = { 8c 14 [2] a8 1a [2] 83 36 [2] ad 14 [2] b9 0f [2] b6 15 [2] a8 08 [2] aa 09 [2] b1 0f [2] ad 08 [2] b1 27 }

  condition:
    any of them
}