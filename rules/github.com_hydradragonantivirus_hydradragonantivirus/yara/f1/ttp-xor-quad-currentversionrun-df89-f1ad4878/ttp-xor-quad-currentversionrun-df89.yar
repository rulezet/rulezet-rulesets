rule TTP_XOR_QUAD_CurrentVersionRun_df89 {
  strings:
    $key_df89 = { 8c e6 [2] a8 e8 [2] 83 c4 [2] ad e6 [2] b9 fd [2] b6 e7 [2] a8 fa [2] aa fb [2] b1 fd [2] ad fa [2] b1 d5 }

  condition:
    any of them
}