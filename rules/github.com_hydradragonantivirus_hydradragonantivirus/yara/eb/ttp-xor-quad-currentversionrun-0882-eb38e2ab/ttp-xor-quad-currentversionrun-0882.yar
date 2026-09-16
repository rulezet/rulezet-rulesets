rule TTP_XOR_QUAD_CurrentVersionRun_0882 {
  strings:
    $key_0882 = { 5b ed [2] 7f e3 [2] 54 cf [2] 7a ed [2] 6e f6 [2] 61 ec [2] 7f f1 [2] 7d f0 [2] 66 f6 [2] 7a f1 [2] 66 de }

  condition:
    any of them
}