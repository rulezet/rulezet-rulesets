rule TTP_XOR_QUAD_CurrentVersionRun_7882 {
  strings:
    $key_7882 = { 2b ed [2] 0f e3 [2] 24 cf [2] 0a ed [2] 1e f6 [2] 11 ec [2] 0f f1 [2] 0d f0 [2] 16 f6 [2] 0a f1 [2] 16 de }

  condition:
    any of them
}