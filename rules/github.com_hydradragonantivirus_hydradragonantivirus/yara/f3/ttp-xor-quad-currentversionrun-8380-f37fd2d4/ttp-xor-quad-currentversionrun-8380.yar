rule TTP_XOR_QUAD_CurrentVersionRun_8380 {
  strings:
    $key_8380 = { d0 ef [2] f4 e1 [2] df cd [2] f1 ef [2] e5 f4 [2] ea ee [2] f4 f3 [2] f6 f2 [2] ed f4 [2] f1 f3 [2] ed dc }

  condition:
    any of them
}