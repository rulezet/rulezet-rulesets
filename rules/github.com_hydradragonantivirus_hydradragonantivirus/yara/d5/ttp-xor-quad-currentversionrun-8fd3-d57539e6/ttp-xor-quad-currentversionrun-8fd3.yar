rule TTP_XOR_QUAD_CurrentVersionRun_8fd3 {
  strings:
    $key_8fd3 = { dc bc [2] f8 b2 [2] d3 9e [2] fd bc [2] e9 a7 [2] e6 bd [2] f8 a0 [2] fa a1 [2] e1 a7 [2] fd a0 [2] e1 8f }

  condition:
    any of them
}