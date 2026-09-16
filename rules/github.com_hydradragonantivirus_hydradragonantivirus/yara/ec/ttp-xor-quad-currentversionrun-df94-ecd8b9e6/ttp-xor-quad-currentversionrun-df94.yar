rule TTP_XOR_QUAD_CurrentVersionRun_df94 {
  strings:
    $key_df94 = { 8c fb [2] a8 f5 [2] 83 d9 [2] ad fb [2] b9 e0 [2] b6 fa [2] a8 e7 [2] aa e6 [2] b1 e0 [2] ad e7 [2] b1 c8 }

  condition:
    any of them
}