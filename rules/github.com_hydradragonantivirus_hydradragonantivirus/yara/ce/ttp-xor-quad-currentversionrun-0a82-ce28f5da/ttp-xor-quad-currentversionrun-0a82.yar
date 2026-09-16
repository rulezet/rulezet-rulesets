rule TTP_XOR_QUAD_CurrentVersionRun_0a82 {
  strings:
    $key_0a82 = { 59 ed [2] 7d e3 [2] 56 cf [2] 78 ed [2] 6c f6 [2] 63 ec [2] 7d f1 [2] 7f f0 [2] 64 f6 [2] 78 f1 [2] 64 de }

  condition:
    any of them
}