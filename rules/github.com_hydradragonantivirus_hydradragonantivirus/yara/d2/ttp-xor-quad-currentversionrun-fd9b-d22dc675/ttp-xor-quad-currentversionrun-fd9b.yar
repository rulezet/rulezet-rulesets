rule TTP_XOR_QUAD_CurrentVersionRun_fd9b {
  strings:
    $key_fd9b = { ae f4 [2] 8a fa [2] a1 d6 [2] 8f f4 [2] 9b ef [2] 94 f5 [2] 8a e8 [2] 88 e9 [2] 93 ef [2] 8f e8 [2] 93 c7 }

  condition:
    any of them
}