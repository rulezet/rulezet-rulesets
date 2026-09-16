rule TTP_XOR_QUAD_CurrentVersionRun_83ba {
  strings:
    $key_83ba = { d0 d5 [2] f4 db [2] df f7 [2] f1 d5 [2] e5 ce [2] ea d4 [2] f4 c9 [2] f6 c8 [2] ed ce [2] f1 c9 [2] ed e6 }

  condition:
    any of them
}