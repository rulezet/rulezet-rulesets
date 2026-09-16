rule TTP_XOR_QUAD_CurrentVersionRun_8398 {
  strings:
    $key_8398 = { d0 f7 [2] f4 f9 [2] df d5 [2] f1 f7 [2] e5 ec [2] ea f6 [2] f4 eb [2] f6 ea [2] ed ec [2] f1 eb [2] ed c4 }

  condition:
    any of them
}