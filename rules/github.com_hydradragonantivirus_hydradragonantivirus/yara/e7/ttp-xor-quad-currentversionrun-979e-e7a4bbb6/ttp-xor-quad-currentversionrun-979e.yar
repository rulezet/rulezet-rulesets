rule TTP_XOR_QUAD_CurrentVersionRun_979e {
  strings:
    $key_979e = { c4 f1 [2] e0 ff [2] cb d3 [2] e5 f1 [2] f1 ea [2] fe f0 [2] e0 ed [2] e2 ec [2] f9 ea [2] e5 ed [2] f9 c2 }

  condition:
    any of them
}