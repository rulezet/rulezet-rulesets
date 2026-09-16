rule TTP_XOR_QUAD_CurrentVersionRun_ae9e {
  strings:
    $key_ae9e = { fd f1 [2] d9 ff [2] f2 d3 [2] dc f1 [2] c8 ea [2] c7 f0 [2] d9 ed [2] db ec [2] c0 ea [2] dc ed [2] c0 c2 }

  condition:
    any of them
}