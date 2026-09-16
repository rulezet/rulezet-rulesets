rule TTP_XOR_QUAD_CurrentVersionRun_ed94 {
  strings:
    $key_ed94 = { be fb [2] 9a f5 [2] b1 d9 [2] 9f fb [2] 8b e0 [2] 84 fa [2] 9a e7 [2] 98 e6 [2] 83 e0 [2] 9f e7 [2] 83 c8 }

  condition:
    any of them
}