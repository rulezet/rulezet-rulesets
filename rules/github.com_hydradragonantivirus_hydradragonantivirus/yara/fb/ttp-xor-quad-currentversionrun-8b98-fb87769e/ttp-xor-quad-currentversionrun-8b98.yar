rule TTP_XOR_QUAD_CurrentVersionRun_8b98 {
  strings:
    $key_8b98 = { d8 f7 [2] fc f9 [2] d7 d5 [2] f9 f7 [2] ed ec [2] e2 f6 [2] fc eb [2] fe ea [2] e5 ec [2] f9 eb [2] e5 c4 }

  condition:
    any of them
}