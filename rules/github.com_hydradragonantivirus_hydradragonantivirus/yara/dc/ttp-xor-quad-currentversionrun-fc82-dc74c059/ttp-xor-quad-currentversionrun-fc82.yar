rule TTP_XOR_QUAD_CurrentVersionRun_fc82 {
  strings:
    $key_fc82 = { af ed [2] 8b e3 [2] a0 cf [2] 8e ed [2] 9a f6 [2] 95 ec [2] 8b f1 [2] 89 f0 [2] 92 f6 [2] 8e f1 [2] 92 de }

  condition:
    any of them
}