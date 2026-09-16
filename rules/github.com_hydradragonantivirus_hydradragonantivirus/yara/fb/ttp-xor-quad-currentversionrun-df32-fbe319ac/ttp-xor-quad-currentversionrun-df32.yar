rule TTP_XOR_QUAD_CurrentVersionRun_df32 {
  strings:
    $key_df32 = { 8c 5d [2] a8 53 [2] 83 7f [2] ad 5d [2] b9 46 [2] b6 5c [2] a8 41 [2] aa 40 [2] b1 46 [2] ad 41 [2] b1 6e }

  condition:
    any of them
}