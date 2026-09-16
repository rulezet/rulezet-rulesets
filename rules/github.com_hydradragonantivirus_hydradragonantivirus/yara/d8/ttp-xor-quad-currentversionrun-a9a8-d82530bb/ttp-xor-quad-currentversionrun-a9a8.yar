rule TTP_XOR_QUAD_CurrentVersionRun_a9a8 {
  strings:
    $key_a9a8 = { fa c7 [2] de c9 [2] f5 e5 [2] db c7 [2] cf dc [2] c0 c6 [2] de db [2] dc da [2] c7 dc [2] db db [2] c7 f4 }

  condition:
    any of them
}