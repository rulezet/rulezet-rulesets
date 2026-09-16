rule TTP_XOR_QUAD_CurrentVersionRun_fd85 {
  strings:
    $key_fd85 = { ae ea [2] 8a e4 [2] a1 c8 [2] 8f ea [2] 9b f1 [2] 94 eb [2] 8a f6 [2] 88 f7 [2] 93 f1 [2] 8f f6 [2] 93 d9 }

  condition:
    any of them
}