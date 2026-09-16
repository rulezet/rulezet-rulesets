rule TTP_XOR_QUAD_CurrentVersionRun_839d {
  strings:
    $key_839d = { d0 f2 [2] f4 fc [2] df d0 [2] f1 f2 [2] e5 e9 [2] ea f3 [2] f4 ee [2] f6 ef [2] ed e9 [2] f1 ee [2] ed c1 }

  condition:
    any of them
}