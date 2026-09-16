rule TTP_XOR_QUAD_CurrentVersionRun_5582 {
  strings:
    $key_5582 = { 06 ed [2] 22 e3 [2] 09 cf [2] 27 ed [2] 33 f6 [2] 3c ec [2] 22 f1 [2] 20 f0 [2] 3b f6 [2] 27 f1 [2] 3b de }

  condition:
    any of them
}