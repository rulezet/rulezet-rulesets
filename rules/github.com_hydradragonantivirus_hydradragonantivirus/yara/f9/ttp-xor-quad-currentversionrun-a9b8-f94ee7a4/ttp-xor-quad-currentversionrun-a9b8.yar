rule TTP_XOR_QUAD_CurrentVersionRun_a9b8 {
  strings:
    $key_a9b8 = { fa d7 [2] de d9 [2] f5 f5 [2] db d7 [2] cf cc [2] c0 d6 [2] de cb [2] dc ca [2] c7 cc [2] db cb [2] c7 e4 }

  condition:
    any of them
}