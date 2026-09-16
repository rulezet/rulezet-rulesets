rule TTP_XOR_QUAD_CurrentVersionRun_eba6 {
  strings:
    $key_eba6 = { b8 c9 [2] 9c c7 [2] b7 eb [2] 99 c9 [2] 8d d2 [2] 82 c8 [2] 9c d5 [2] 9e d4 [2] 85 d2 [2] 99 d5 [2] 85 fa }

  condition:
    any of them
}