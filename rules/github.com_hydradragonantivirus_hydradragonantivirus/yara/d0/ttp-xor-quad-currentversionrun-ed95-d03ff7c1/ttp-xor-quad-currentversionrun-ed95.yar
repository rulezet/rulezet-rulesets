rule TTP_XOR_QUAD_CurrentVersionRun_ed95 {
  strings:
    $key_ed95 = { be fa [2] 9a f4 [2] b1 d8 [2] 9f fa [2] 8b e1 [2] 84 fb [2] 9a e6 [2] 98 e7 [2] 83 e1 [2] 9f e6 [2] 83 c9 }

  condition:
    any of them
}