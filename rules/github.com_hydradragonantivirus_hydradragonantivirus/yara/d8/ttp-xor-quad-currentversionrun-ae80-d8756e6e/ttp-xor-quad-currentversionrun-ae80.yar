rule TTP_XOR_QUAD_CurrentVersionRun_ae80 {
  strings:
    $key_ae80 = { fd ef [2] d9 e1 [2] f2 cd [2] dc ef [2] c8 f4 [2] c7 ee [2] d9 f3 [2] db f2 [2] c0 f4 [2] dc f3 [2] c0 dc }

  condition:
    any of them
}