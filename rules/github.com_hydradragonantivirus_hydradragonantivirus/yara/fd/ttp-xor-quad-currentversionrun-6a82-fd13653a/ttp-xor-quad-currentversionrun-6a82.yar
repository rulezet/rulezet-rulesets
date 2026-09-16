rule TTP_XOR_QUAD_CurrentVersionRun_6a82 {
  strings:
    $key_6a82 = { 39 ed [2] 1d e3 [2] 36 cf [2] 18 ed [2] 0c f6 [2] 03 ec [2] 1d f1 [2] 1f f0 [2] 04 f6 [2] 18 f1 [2] 04 de }

  condition:
    any of them
}