rule TTP_XOR_QUAD_CurrentVersionRun_1f82 {
  strings:
    $key_1f82 = { 4c ed [2] 68 e3 [2] 43 cf [2] 6d ed [2] 79 f6 [2] 76 ec [2] 68 f1 [2] 6a f0 [2] 71 f6 [2] 6d f1 [2] 71 de }

  condition:
    any of them
}