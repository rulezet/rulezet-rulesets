rule TTP_XOR_QUAD_CurrentVersionRun_2382 {
  strings:
    $key_2382 = { 70 ed [2] 54 e3 [2] 7f cf [2] 51 ed [2] 45 f6 [2] 4a ec [2] 54 f1 [2] 56 f0 [2] 4d f6 [2] 51 f1 [2] 4d de }

  condition:
    any of them
}