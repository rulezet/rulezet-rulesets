rule TTP_XOR_QUAD_CurrentVersionRun_fd8b {
  strings:
    $key_fd8b = { ae e4 [2] 8a ea [2] a1 c6 [2] 8f e4 [2] 9b ff [2] 94 e5 [2] 8a f8 [2] 88 f9 [2] 93 ff [2] 8f f8 [2] 93 d7 }

  condition:
    any of them
}