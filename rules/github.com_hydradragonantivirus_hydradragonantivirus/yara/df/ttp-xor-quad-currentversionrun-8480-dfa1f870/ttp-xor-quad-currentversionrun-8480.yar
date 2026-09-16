rule TTP_XOR_QUAD_CurrentVersionRun_8480 {
  strings:
    $key_8480 = { d7 ef [2] f3 e1 [2] d8 cd [2] f6 ef [2] e2 f4 [2] ed ee [2] f3 f3 [2] f1 f2 [2] ea f4 [2] f6 f3 [2] ea dc }

  condition:
    any of them
}