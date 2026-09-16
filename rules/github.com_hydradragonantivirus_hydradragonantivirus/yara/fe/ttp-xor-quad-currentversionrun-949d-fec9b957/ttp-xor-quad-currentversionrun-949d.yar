rule TTP_XOR_QUAD_CurrentVersionRun_949d {
  strings:
    $key_949d = { c7 f2 [2] e3 fc [2] c8 d0 [2] e6 f2 [2] f2 e9 [2] fd f3 [2] e3 ee [2] e1 ef [2] fa e9 [2] e6 ee [2] fa c1 }

  condition:
    any of them
}