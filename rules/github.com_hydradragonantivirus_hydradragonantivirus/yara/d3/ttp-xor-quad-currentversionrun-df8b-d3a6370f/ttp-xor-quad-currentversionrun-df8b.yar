rule TTP_XOR_QUAD_CurrentVersionRun_df8b {
  strings:
    $key_df8b = { 8c e4 [2] a8 ea [2] 83 c6 [2] ad e4 [2] b9 ff [2] b6 e5 [2] a8 f8 [2] aa f9 [2] b1 ff [2] ad f8 [2] b1 d7 }

  condition:
    any of them
}