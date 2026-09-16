rule TTP_XOR_QUAD_CurrentVersionRun_ae89 {
  strings:
    $key_ae89 = { fd e6 [2] d9 e8 [2] f2 c4 [2] dc e6 [2] c8 fd [2] c7 e7 [2] d9 fa [2] db fb [2] c0 fd [2] dc fa [2] c0 d5 }

  condition:
    any of them
}