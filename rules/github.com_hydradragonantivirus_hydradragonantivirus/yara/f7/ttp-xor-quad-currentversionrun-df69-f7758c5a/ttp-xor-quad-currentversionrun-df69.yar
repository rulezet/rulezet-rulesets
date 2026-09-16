rule TTP_XOR_QUAD_CurrentVersionRun_df69 {
  strings:
    $key_df69 = { 8c 06 [2] a8 08 [2] 83 24 [2] ad 06 [2] b9 1d [2] b6 07 [2] a8 1a [2] aa 1b [2] b1 1d [2] ad 1a [2] b1 35 }

  condition:
    any of them
}