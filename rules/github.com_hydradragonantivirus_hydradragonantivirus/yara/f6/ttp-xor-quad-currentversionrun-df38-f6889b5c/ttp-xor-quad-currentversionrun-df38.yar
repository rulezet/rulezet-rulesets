rule TTP_XOR_QUAD_CurrentVersionRun_df38 {
  strings:
    $key_df38 = { 8c 57 [2] a8 59 [2] 83 75 [2] ad 57 [2] b9 4c [2] b6 56 [2] a8 4b [2] aa 4a [2] b1 4c [2] ad 4b [2] b1 64 }

  condition:
    any of them
}