rule TTP_XOR_QUAD_CurrentVersionRun_d888 {
  strings:
    $key_d888 = { 8b e7 [2] af e9 [2] 84 c5 [2] aa e7 [2] be fc [2] b1 e6 [2] af fb [2] ad fa [2] b6 fc [2] aa fb [2] b6 d4 }

  condition:
    any of them
}