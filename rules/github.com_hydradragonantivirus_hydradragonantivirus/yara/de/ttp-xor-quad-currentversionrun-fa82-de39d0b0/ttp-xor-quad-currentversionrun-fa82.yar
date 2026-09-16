rule TTP_XOR_QUAD_CurrentVersionRun_fa82 {
  strings:
    $key_fa82 = { a9 ed [2] 8d e3 [2] a6 cf [2] 88 ed [2] 9c f6 [2] 93 ec [2] 8d f1 [2] 8f f0 [2] 94 f6 [2] 88 f1 [2] 94 de }

  condition:
    any of them
}