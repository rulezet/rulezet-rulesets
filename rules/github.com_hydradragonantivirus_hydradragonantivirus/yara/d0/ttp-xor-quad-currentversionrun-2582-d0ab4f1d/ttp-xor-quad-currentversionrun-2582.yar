rule TTP_XOR_QUAD_CurrentVersionRun_2582 {
  strings:
    $key_2582 = { 76 ed [2] 52 e3 [2] 79 cf [2] 57 ed [2] 43 f6 [2] 4c ec [2] 52 f1 [2] 50 f0 [2] 4b f6 [2] 57 f1 [2] 4b de }

  condition:
    any of them
}