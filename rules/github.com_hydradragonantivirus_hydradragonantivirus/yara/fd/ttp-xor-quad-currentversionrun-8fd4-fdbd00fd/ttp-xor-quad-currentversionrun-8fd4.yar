rule TTP_XOR_QUAD_CurrentVersionRun_8fd4 {
  strings:
    $key_8fd4 = { dc bb [2] f8 b5 [2] d3 99 [2] fd bb [2] e9 a0 [2] e6 ba [2] f8 a7 [2] fa a6 [2] e1 a0 [2] fd a7 [2] e1 88 }

  condition:
    any of them
}