rule TTP_XOR_QUAD_CurrentVersionRun_df47 {
  strings:
    $key_df47 = { 8c 28 [2] a8 26 [2] 83 0a [2] ad 28 [2] b9 33 [2] b6 29 [2] a8 34 [2] aa 35 [2] b1 33 [2] ad 34 [2] b1 1b }

  condition:
    any of them
}