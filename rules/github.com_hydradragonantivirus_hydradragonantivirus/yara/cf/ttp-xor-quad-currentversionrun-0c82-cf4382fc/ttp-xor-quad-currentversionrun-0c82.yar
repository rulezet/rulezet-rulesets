rule TTP_XOR_QUAD_CurrentVersionRun_0c82 {
  strings:
    $key_0c82 = { 5f ed [2] 7b e3 [2] 50 cf [2] 7e ed [2] 6a f6 [2] 65 ec [2] 7b f1 [2] 79 f0 [2] 62 f6 [2] 7e f1 [2] 62 de }

  condition:
    any of them
}