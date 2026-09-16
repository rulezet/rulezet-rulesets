rule TTP_XOR_QUAD_CurrentVersionRun_849c {
  strings:
    $key_849c = { d7 f3 [2] f3 fd [2] d8 d1 [2] f6 f3 [2] e2 e8 [2] ed f2 [2] f3 ef [2] f1 ee [2] ea e8 [2] f6 ef [2] ea c0 }

  condition:
    any of them
}