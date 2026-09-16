rule TTP_XOR_QUAD_CurrentVersionRun_df67 {
  strings:
    $key_df67 = { 8c 08 [2] a8 06 [2] 83 2a [2] ad 08 [2] b9 13 [2] b6 09 [2] a8 14 [2] aa 15 [2] b1 13 [2] ad 14 [2] b1 3b }

  condition:
    any of them
}