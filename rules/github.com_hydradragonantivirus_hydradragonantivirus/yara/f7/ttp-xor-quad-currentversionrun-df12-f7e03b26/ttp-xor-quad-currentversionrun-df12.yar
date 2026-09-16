rule TTP_XOR_QUAD_CurrentVersionRun_df12 {
  strings:
    $key_df12 = { 8c 7d [2] a8 73 [2] 83 5f [2] ad 7d [2] b9 66 [2] b6 7c [2] a8 61 [2] aa 60 [2] b1 66 [2] ad 61 [2] b1 4e }

  condition:
    any of them
}