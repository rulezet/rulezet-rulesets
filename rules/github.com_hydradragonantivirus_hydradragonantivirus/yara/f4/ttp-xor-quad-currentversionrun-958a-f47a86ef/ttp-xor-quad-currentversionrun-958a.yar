rule TTP_XOR_QUAD_CurrentVersionRun_958a {
  strings:
    $key_958a = { c6 e5 [2] e2 eb [2] c9 c7 [2] e7 e5 [2] f3 fe [2] fc e4 [2] e2 f9 [2] e0 f8 [2] fb fe [2] e7 f9 [2] fb d6 }

  condition:
    any of them
}