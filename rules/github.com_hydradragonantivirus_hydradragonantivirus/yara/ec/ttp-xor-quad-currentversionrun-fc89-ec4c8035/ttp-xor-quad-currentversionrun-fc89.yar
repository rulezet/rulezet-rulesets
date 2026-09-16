rule TTP_XOR_QUAD_CurrentVersionRun_fc89 {
  strings:
    $key_fc89 = { af e6 [2] 8b e8 [2] a0 c4 [2] 8e e6 [2] 9a fd [2] 95 e7 [2] 8b fa [2] 89 fb [2] 92 fd [2] 8e fa [2] 92 d5 }

  condition:
    any of them
}