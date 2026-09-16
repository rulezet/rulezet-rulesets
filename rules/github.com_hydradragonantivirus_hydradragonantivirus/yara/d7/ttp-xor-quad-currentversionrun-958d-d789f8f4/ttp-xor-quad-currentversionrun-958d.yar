rule TTP_XOR_QUAD_CurrentVersionRun_958d {
  strings:
    $key_958d = { c6 e2 [2] e2 ec [2] c9 c0 [2] e7 e2 [2] f3 f9 [2] fc e3 [2] e2 fe [2] e0 ff [2] fb f9 [2] e7 fe [2] fb d1 }

  condition:
    any of them
}