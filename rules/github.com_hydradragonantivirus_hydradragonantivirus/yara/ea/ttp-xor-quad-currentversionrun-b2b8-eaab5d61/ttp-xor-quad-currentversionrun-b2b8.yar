rule TTP_XOR_QUAD_CurrentVersionRun_b2b8 {
  strings:
    $key_b2b8 = { e1 d7 [2] c5 d9 [2] ee f5 [2] c0 d7 [2] d4 cc [2] db d6 [2] c5 cb [2] c7 ca [2] dc cc [2] c0 cb [2] dc e4 }

  condition:
    any of them
}