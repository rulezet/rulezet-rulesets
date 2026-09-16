rule TTP_XOR_QUAD_CurrentVersionRun_8b84 {
  strings:
    $key_8b84 = { d8 eb [2] fc e5 [2] d7 c9 [2] f9 eb [2] ed f0 [2] e2 ea [2] fc f7 [2] fe f6 [2] e5 f0 [2] f9 f7 [2] e5 d8 }

  condition:
    any of them
}