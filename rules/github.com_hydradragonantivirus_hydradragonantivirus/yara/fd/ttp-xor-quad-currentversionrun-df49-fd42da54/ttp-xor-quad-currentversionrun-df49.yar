rule TTP_XOR_QUAD_CurrentVersionRun_df49 {
  strings:
    $key_df49 = { 8c 26 [2] a8 28 [2] 83 04 [2] ad 26 [2] b9 3d [2] b6 27 [2] a8 3a [2] aa 3b [2] b1 3d [2] ad 3a [2] b1 15 }

  condition:
    any of them
}