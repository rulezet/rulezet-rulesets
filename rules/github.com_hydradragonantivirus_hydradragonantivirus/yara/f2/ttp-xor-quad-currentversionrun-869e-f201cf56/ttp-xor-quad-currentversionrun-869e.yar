rule TTP_XOR_QUAD_CurrentVersionRun_869e {
  strings:
    $key_869e = { d5 f1 [2] f1 ff [2] da d3 [2] f4 f1 [2] e0 ea [2] ef f0 [2] f1 ed [2] f3 ec [2] e8 ea [2] f4 ed [2] e8 c2 }

  condition:
    any of them
}