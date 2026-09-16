rule TTP_XOR_QUAD_CurrentVersionRun_ac8d {
  strings:
    $key_ac8d = { ff e2 [2] db ec [2] f0 c0 [2] de e2 [2] ca f9 [2] c5 e3 [2] db fe [2] d9 ff [2] c2 f9 [2] de fe [2] c2 d1 }

  condition:
    any of them
}