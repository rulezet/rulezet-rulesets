rule TTP_XOR_QUAD_CurrentVersionRun_8484 {
  strings:
    $key_8484 = { d7 eb [2] f3 e5 [2] d8 c9 [2] f6 eb [2] e2 f0 [2] ed ea [2] f3 f7 [2] f1 f6 [2] ea f0 [2] f6 f7 [2] ea d8 }

  condition:
    any of them
}