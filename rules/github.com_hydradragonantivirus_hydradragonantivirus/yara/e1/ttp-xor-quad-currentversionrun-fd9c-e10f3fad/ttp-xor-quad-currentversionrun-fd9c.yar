rule TTP_XOR_QUAD_CurrentVersionRun_fd9c {
  strings:
    $key_fd9c = { ae f3 [2] 8a fd [2] a1 d1 [2] 8f f3 [2] 9b e8 [2] 94 f2 [2] 8a ef [2] 88 ee [2] 93 e8 [2] 8f ef [2] 93 c0 }

  condition:
    any of them
}