rule TTP_XOR_QUAD_CurrentVersionRun_df97 {
  strings:
    $key_df97 = { 8c f8 [2] a8 f6 [2] 83 da [2] ad f8 [2] b9 e3 [2] b6 f9 [2] a8 e4 [2] aa e5 [2] b1 e3 [2] ad e4 [2] b1 cb }

  condition:
    any of them
}