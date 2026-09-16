rule TTP_XOR_QUAD_CurrentVersionRun_4f82 {
  strings:
    $key_4f82 = { 1c ed [2] 38 e3 [2] 13 cf [2] 3d ed [2] 29 f6 [2] 26 ec [2] 38 f1 [2] 3a f0 [2] 21 f6 [2] 3d f1 [2] 21 de }

  condition:
    any of them
}