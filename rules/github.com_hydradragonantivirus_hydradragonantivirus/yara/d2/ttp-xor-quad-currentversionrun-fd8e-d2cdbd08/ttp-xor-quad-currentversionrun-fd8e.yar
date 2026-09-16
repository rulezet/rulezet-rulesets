rule TTP_XOR_QUAD_CurrentVersionRun_fd8e {
  strings:
    $key_fd8e = { ae e1 [2] 8a ef [2] a1 c3 [2] 8f e1 [2] 9b fa [2] 94 e0 [2] 8a fd [2] 88 fc [2] 93 fa [2] 8f fd [2] 93 d2 }

  condition:
    any of them
}