rule TTP_XOR_QUAD_CurrentVersionRun_84ad {
  strings:
    $key_84ad = { d7 c2 [2] f3 cc [2] d8 e0 [2] f6 c2 [2] e2 d9 [2] ed c3 [2] f3 de [2] f1 df [2] ea d9 [2] f6 de [2] ea f1 }

  condition:
    any of them
}