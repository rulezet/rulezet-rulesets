rule TTP_XOR_QUAD_CurrentVersionRun_4e82 {
  strings:
    $key_4e82 = { 1d ed [2] 39 e3 [2] 12 cf [2] 3c ed [2] 28 f6 [2] 27 ec [2] 39 f1 [2] 3b f0 [2] 20 f6 [2] 3c f1 [2] 20 de }

  condition:
    any of them
}