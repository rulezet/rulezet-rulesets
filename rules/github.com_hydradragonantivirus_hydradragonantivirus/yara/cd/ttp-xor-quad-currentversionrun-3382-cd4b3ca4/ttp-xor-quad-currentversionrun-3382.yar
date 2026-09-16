rule TTP_XOR_QUAD_CurrentVersionRun_3382 {
  strings:
    $key_3382 = { 60 ed [2] 44 e3 [2] 6f cf [2] 41 ed [2] 55 f6 [2] 5a ec [2] 44 f1 [2] 46 f0 [2] 5d f6 [2] 41 f1 [2] 5d de }

  condition:
    any of them
}