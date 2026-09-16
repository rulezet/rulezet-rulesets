rule TTP_XOR_QUAD_CurrentVersionRun_fd82 {
  strings:
    $key_fd82 = { ae ed [2] 8a e3 [2] a1 cf [2] 8f ed [2] 9b f6 [2] 94 ec [2] 8a f1 [2] 88 f0 [2] 93 f6 [2] 8f f1 [2] 93 de }

  condition:
    any of them
}