rule TTP_XOR_QUAD_CurrentVersionRun_8b9e {
  strings:
    $key_8b9e = { d8 f1 [2] fc ff [2] d7 d3 [2] f9 f1 [2] ed ea [2] e2 f0 [2] fc ed [2] fe ec [2] e5 ea [2] f9 ed [2] e5 c2 }

  condition:
    any of them
}