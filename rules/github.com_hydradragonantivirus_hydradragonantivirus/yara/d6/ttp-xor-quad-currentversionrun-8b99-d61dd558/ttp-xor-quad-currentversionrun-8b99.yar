rule TTP_XOR_QUAD_CurrentVersionRun_8b99 {
  strings:
    $key_8b99 = { d8 f6 [2] fc f8 [2] d7 d4 [2] f9 f6 [2] ed ed [2] e2 f7 [2] fc ea [2] fe eb [2] e5 ed [2] f9 ea [2] e5 c5 }

  condition:
    any of them
}