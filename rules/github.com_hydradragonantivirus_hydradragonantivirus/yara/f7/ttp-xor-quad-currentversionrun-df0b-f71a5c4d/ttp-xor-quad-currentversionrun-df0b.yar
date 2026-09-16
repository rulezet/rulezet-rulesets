rule TTP_XOR_QUAD_CurrentVersionRun_df0b {
  strings:
    $key_df0b = { 8c 64 [2] a8 6a [2] 83 46 [2] ad 64 [2] b9 7f [2] b6 65 [2] a8 78 [2] aa 79 [2] b1 7f [2] ad 78 [2] b1 57 }

  condition:
    any of them
}