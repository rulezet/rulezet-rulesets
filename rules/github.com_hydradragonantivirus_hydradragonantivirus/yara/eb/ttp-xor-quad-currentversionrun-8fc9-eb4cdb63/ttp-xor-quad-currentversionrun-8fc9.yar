rule TTP_XOR_QUAD_CurrentVersionRun_8fc9 {
  strings:
    $key_8fc9 = { dc a6 [2] f8 a8 [2] d3 84 [2] fd a6 [2] e9 bd [2] e6 a7 [2] f8 ba [2] fa bb [2] e1 bd [2] fd ba [2] e1 95 }

  condition:
    any of them
}