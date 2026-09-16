rule TTP_XOR_QUAD_CurrentVersionRun_5382 {
  strings:
    $key_5382 = { 00 ed [2] 24 e3 [2] 0f cf [2] 21 ed [2] 35 f6 [2] 3a ec [2] 24 f1 [2] 26 f0 [2] 3d f6 [2] 21 f1 [2] 3d de }

  condition:
    any of them
}