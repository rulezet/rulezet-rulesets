rule TTP_XOR_QUAD_CurrentVersionRun_fd95 {
  strings:
    $key_fd95 = { ae fa [2] 8a f4 [2] a1 d8 [2] 8f fa [2] 9b e1 [2] 94 fb [2] 8a e6 [2] 88 e7 [2] 93 e1 [2] 8f e6 [2] 93 c9 }

  condition:
    any of them
}