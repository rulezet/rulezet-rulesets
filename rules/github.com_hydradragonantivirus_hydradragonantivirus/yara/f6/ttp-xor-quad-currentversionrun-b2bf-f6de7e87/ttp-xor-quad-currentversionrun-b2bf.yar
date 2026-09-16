rule TTP_XOR_QUAD_CurrentVersionRun_b2bf {
  strings:
    $key_b2bf = { e1 d0 [2] c5 de [2] ee f2 [2] c0 d0 [2] d4 cb [2] db d1 [2] c5 cc [2] c7 cd [2] dc cb [2] c0 cc [2] dc e3 }

  condition:
    any of them
}