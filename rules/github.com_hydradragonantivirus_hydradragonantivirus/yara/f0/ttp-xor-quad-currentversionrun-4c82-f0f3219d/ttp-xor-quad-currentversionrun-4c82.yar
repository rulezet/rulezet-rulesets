rule TTP_XOR_QUAD_CurrentVersionRun_4c82 {
  strings:
    $key_4c82 = { 1f ed [2] 3b e3 [2] 10 cf [2] 3e ed [2] 2a f6 [2] 25 ec [2] 3b f1 [2] 39 f0 [2] 22 f6 [2] 3e f1 [2] 22 de }

  condition:
    any of them
}