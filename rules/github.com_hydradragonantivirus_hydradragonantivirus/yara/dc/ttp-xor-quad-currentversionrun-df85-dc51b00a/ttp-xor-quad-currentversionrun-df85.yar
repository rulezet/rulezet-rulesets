rule TTP_XOR_QUAD_CurrentVersionRun_df85 {
  strings:
    $key_df85 = { 8c ea [2] a8 e4 [2] 83 c8 [2] ad ea [2] b9 f1 [2] b6 eb [2] a8 f6 [2] aa f7 [2] b1 f1 [2] ad f6 [2] b1 d9 }

  condition:
    any of them
}