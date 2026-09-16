rule TTP_XOR_QUAD_CurrentVersionRun_df9f {
  strings:
    $key_df9f = { 8c f0 [2] a8 fe [2] 83 d2 [2] ad f0 [2] b9 eb [2] b6 f1 [2] a8 ec [2] aa ed [2] b1 eb [2] ad ec [2] b1 c3 }

  condition:
    any of them
}